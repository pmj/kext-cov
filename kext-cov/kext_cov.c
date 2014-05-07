//
//  kext_cov.c
//  kext-cov
//
//  Created by Phillip Jordan on 05/12/2012.
//  Copyright (c) 2012-2014 Phil Jordan.
//
//  Parts related to outputting the correct sequence of bytes for the gcda file
//  format are loosely based on GCDAProfiling.c in libprofile from the llvm project.
//
//  libprofile/llvm Copyright 2003-2014 LLVM Team
//  See http://llvm.org/ for details.
//
//  Released under the University of Illinois Open Source
//  License. See license.txt for details.

#include "kext_cov.h"
#include "kext_cov_shared.h"
#include "../lib/genccont/src/slist.h"
#include <string.h>
#include <mach/mach_types.h>
#include <sys/kern_control.h>
#include <sys/errno.h>
#include <libkern/libkern.h>
#include <stdbool.h>
#include <pexpert/pexpert.h>
#include <kern/thread.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <libkern/OSMalloc.h>

#define KCOV_UNUSED __attribute__((unused))

#define kcov_alloc(type, tag) \
({ (type*)OSMalloc(sizeof(type), (tag)); })

kern_return_t kext_cov_start(kmod_info_t * ki, void *d);
kern_return_t kext_cov_stop(kmod_info_t *ki, void *d);

static errno_t kext_cov_connect(
	kern_ctl_ref kctlref,
	struct sockaddr_ctl* sac,
	void** unitinfo);

static errno_t kext_cov_disconnect(
	kern_ctl_ref kctlref,
	u_int32_t unit,
	void* unitinfo);


struct kern_ctl_reg ctl_reg =
{
	"com.ssdcache.kext-cov",
	0 /* id */, 0 /* unit */,
	CTL_FLAG_PRIVILEGED,
	0 /* send size*/, 0 /* receive size */,
	kext_cov_connect,
	kext_cov_disconnect,
	NULL /* send */,
	NULL /* setopt */,
	NULL /* getopt */
};

struct kext_cov_export_context
{
	genc_slist_head_t context_list_head;
	
	thread_t export_thread;
	
  kern_ctl_ref ctl_ref;
	uint32_t unit;

	const char* cur_file;
	
	mbuf_t cur_packet;
	uint32_t cur_packet_data;
	uint8_t cur_packet_type;
	
	bool abort_export;
};
typedef struct kext_cov_export_context kext_cov_export_context_t;

typedef void(atexit_fn_t)(void);

struct kext_cov_write_flush
{
	genc_slist_head_t head;
	
  writeout_fn_t writeout_fn;
	flush_fn_t flush_fn;
};
typedef struct kext_cov_write_flush kext_cov_write_flush_t;

struct kext_cov_state
{
	kern_ctl_ref ctl_ref;

	OSMallocTag tag;
	// Protects all items below
	IOLock* lock;
	
	int exports_in_progress;
	// Linked list of kext_cov_export_context_t objects
	genc_slist_head_t* contexts;
	
	// Linked list of kext_cov_write_flush_t objects
	genc_slist_head_t* write_flush_fns;
	unsigned write_flush_fns_walks_in_progress;
	
	/* Functions to call for dumping stats. Can be rearranged only if
	 * exports_in_progress == 0; zero out and/or append elements otherwise.
	 */
	atexit_fn_t** atexit_functions;
	// Index of item past the last nonzero one (can be == atexit_functions_len)
	uint32_t atexit_functions_tail;
	// Index of first NULL item in array.
	uint32_t atexit_functions_first_null;
	// Allocated array length
	uint32_t atexit_functions_len;
};

static struct kext_cov_state state =
{
	.ctl_ref = NULL,
	.tag = NULL,
	.lock = NULL,
	.exports_in_progress = 0,
	.contexts = NULL,
	.write_flush_fns = NULL,
	.write_flush_fns_walks_in_progress = 0,
	.atexit_functions = NULL,
	.atexit_functions_tail = 0,
	.atexit_functions_first_null = 0,
	.atexit_functions_len = 0
};

static const unsigned KCOV_SEND_RETRY_DELAY_USEC = 10000;
static const unsigned KCOV_SEND_MAX_RETRIES = 500;

static size_t mbuf_chain_len(mbuf_t m)
{
	size_t len = 0;
	for (; m; m = mbuf_next(m))
	{
		len += mbuf_len(m);
	}
	return len;
}

static bool ctl_send_mbuf_blocking(kern_ctl_ref ctl, uint32_t ctl_unit, mbuf_t packet, bool end_of_record)
{
	bool retry = false;
	unsigned retry_count = 0;
	
	do
	{
		retry = false;
		errno_t err = ctl_enqueuembuf(ctl, ctl_unit, packet, end_of_record ? CTL_DATA_EOR : CTL_DATA_NOWAKEUP);
		if (err == ENOBUFS)
		{
			++retry_count;
			retry = retry_count < KCOV_SEND_MAX_RETRIES;
			if (retry)
			{
				IODelay(KCOV_SEND_RETRY_DELAY_USEC);
			}
			else
			{
				kprintf("Timed out trying to send packet %p, length %lu, ctl %p unit %u.\n",
					packet, packet ? mbuf_chain_len(packet) : 0, ctl, ctl_unit);
				mbuf_freem(packet);
				return false;
			}
		}
		else if (err != 0)
		{
			kprintf("write_socket_data: Error %d submitting packet. Packet %p, length %lu, ctl %p, unit %u\n",
				err, packet, packet ? mbuf_chain_len(packet) : 0, ctl, ctl_unit);
			mbuf_freem(packet);
		}
	} while (retry);
	return true;
}

static const size_t KCOV_PACKET_HEADER_SIZE = sizeof(struct kcov_packet_header);
_Static_assert(sizeof(uint8_t) + sizeof(uint32_t) == sizeof(struct kcov_packet_header), "");

static void submit_current_packet(kext_cov_export_context_t* context)
{
	struct kcov_packet_header header = { context->cur_packet_type };
	memcpy(header.packet_size_u32le, &context->cur_packet_data, sizeof(header.packet_size_u32le));
		
	errno_t err = mbuf_copyback(context->cur_packet, 0, KCOV_PACKET_HEADER_SIZE, &header, MBUF_WAITOK);
	if (err != 0)
		kprintf("submit_current_packet(): mbuf_copyback() failed with code %d\n", err);

	bool ok = ctl_send_mbuf_blocking(context->ctl_ref, context->unit, context->cur_packet, true);
	context->cur_packet = NULL;
	context->cur_packet_data = 0;
	context->cur_packet_type = 0;
	if (!ok)
		context->abort_export = true;
}

static void append_packet_data(
	kext_cov_export_context_t* context, uint8_t packet_type, const void* data, size_t len, bool end)
{
	if (context->abort_export)
		return;
	if (packet_type != context->cur_packet_type || context->cur_packet_data + len + KCOV_PACKET_HEADER_SIZE > KEXT_COV_MAX_PACKET_SIZE)
	{
		if (context->cur_packet_data > 0)
		{
			submit_current_packet(context);
		}
	}
	
	const char* remain_data = data;
	do
	{
		if (!context->cur_packet)
		{
			mbuf_t packet = NULL;
			errno_t err = mbuf_allocpacket(MBUF_WAITOK, KCOV_PACKET_HEADER_SIZE, NULL, &packet);
			if (err != 0)
			{
				kprintf("append_packet_data: Failed to alloc packet: %d\n", err);
				return;
			}
			struct kcov_packet_header hdr = { packet_type };
			err = mbuf_copyback(packet, 0, sizeof(hdr), &hdr, MBUF_WAITOK);
			if (err)
			{
				kprintf("append_packet_data: Failed to set header.\n");
				return;
			}
			context->cur_packet = packet;
			context->cur_packet_type = packet_type;
			context->cur_packet_data = 0;
		}
		
		mbuf_t packet = context->cur_packet;
		size_t offset = KCOV_PACKET_HEADER_SIZE + context->cur_packet_data;
		errno_t err = (len == 0) ? 0 : mbuf_copyback(packet, offset, len, remain_data, MBUF_WAITOK);
		if (err == ENOBUFS)
		{
			size_t buflen = mbuf_chain_len(packet);
			if (buflen > offset + len)
			{
				kprintf("append_packet_data: Warning - mbuf len %lu after ENOBUFS error when appending %lu bytes from offset %lu\n",
					buflen, len, offset);
				buflen = offset + len;
			}
			size_t copied = (buflen - offset);
			context->cur_packet_data += copied;
			remain_data += copied;
			len -= copied;
			
			submit_current_packet(context);
		}
		else if (err != 0)
		{
			kprintf("append_packet_data: Error %d appending data (%p, %lu bytes at offset %lu) to packet %p (len %lu).\n",
				err, remain_data, len, offset, packet, packet ? mbuf_chain_len(packet) : 0lu);
			return;
		}
		else
		{
			// success
			context->cur_packet_data += len;
			break;
		}
	} while (len > 0 && !context->abort_export);
	
	if (end && context->cur_packet && !context->abort_export)
	{
		submit_current_packet(context);
	}
}

static void write_int32(kext_cov_export_context_t* context, uint8_t packet_type, uint32_t i)
{
	append_packet_data(context, packet_type, &i, 4, false);
}

static void write_int64(kext_cov_export_context_t* context, uint8_t packet_type, uint64_t i)
{
	uint32_t lo = (uint32_t)( i & 0x00000000ffffffffllu);
	uint32_t hi = (uint32_t)((i & 0xffffffff00000000llu) >> 32);

  write_int32(context, packet_type, lo);
  write_int32(context, packet_type, hi);
}

static uint32_t length_of_string(const char* s)
{
	return (uint32_t)strlen(s) / 4u + 1u;
}

static void write_string(kext_cov_export_context_t* context, uint8_t packet_type, const char* s)
{
	uint32_t words = length_of_string(s);
	write_int32(context, packet_type, words);
	size_t len = strlen(s);
	append_packet_data(context, packet_type, s, len, false);
	append_packet_data(context, packet_type, "\0\0\0\0", 4 - len % 4, false);
}

static genc_bool_t context_matches_thread(genc_slist_head_t* ctx_head, void* thread)
{
	kext_cov_export_context_t* ctx = genc_container_of_notnull(ctx_head, kext_cov_export_context_t, context_list_head);
	return ctx->export_thread == thread;
}

static kext_cov_export_context_t* context_for_thread(thread_t thread)
{
	IOLockLock(state.lock);
	// yeah, it's a linear search, but the list is usually only one item anyway
	kext_cov_export_context_t* ctx = genc_slist_find_obj(
		state.contexts, kext_cov_export_context_t, context_list_head, context_matches_thread, thread);
	IOLockUnlock(state.lock);
	return ctx;
}

static kext_cov_export_context_t* context_for_current_thread(void)
{
	thread_t thread = current_thread();
	kext_cov_export_context_t* ctx = context_for_thread(thread);
	if (!ctx)
		kprintf("context_for_current_thread(): No export context for thread %p\n", thread);
	return ctx;
}

void llvm_gcda_start_file(const char* filename)
{
	kext_cov_export_context_t* ctx = context_for_current_thread();
	if (!ctx || ctx->abort_export)
		return;
	
	if (ctx->cur_file)
	{
		kprintf("llvm_gcda_start_file(): Warning: trying to start new file %s before end of file %s\n",
			filename, ctx->cur_file);
	}
	ctx->cur_file = filename;
	uint32_t filename_len = (uint32_t)strlen(filename);
	
	append_packet_data(ctx, KCOV_PACKET_FILE_START, filename, filename_len, true);
	
  /* gcda file, version 404*, stamp LLVM. */
  append_packet_data(ctx, KCOV_PACKET_FILE_DATA, "adcg*204MVLL", 12, false);
}

void llvm_gcda_emit_function(uint32_t ident, const char* function_name)
{
	kext_cov_export_context_t* ctx = context_for_current_thread();
	if (!ctx) return;
	
  /* function tag */
  append_packet_data(ctx, KCOV_PACKET_FILE_DATA, "\0\0\0\1", 4, false);
  write_int32(ctx, KCOV_PACKET_FILE_DATA, 2+1+length_of_string(function_name));
  write_int32(ctx, KCOV_PACKET_FILE_DATA, ident);
  write_int32(ctx, KCOV_PACKET_FILE_DATA, 0);
	write_string(ctx, KCOV_PACKET_FILE_DATA, function_name);
}

void llvm_gcda_emit_arcs(uint32_t num_counters, uint64_t* counters)
{
	kext_cov_export_context_t* ctx = context_for_current_thread();
	if (!ctx) return;

  /* counter #1 (arcs) tag */
  append_packet_data(ctx, KCOV_PACKET_FILE_DATA, "\0\0\xa1\1", 4, false);
  write_int32(ctx, KCOV_PACKET_FILE_DATA, num_counters * 2);
  for (uint32_t i = 0; i < num_counters; ++i)
	{
    write_int64(ctx, KCOV_PACKET_FILE_DATA, counters[i]);
  }
}

void llvm_gcda_end_file(void)
{
	kext_cov_export_context_t* ctx = context_for_current_thread();
	if (!ctx) return;

  /* Write out EOF record. */
  append_packet_data(ctx, KCOV_PACKET_FILE_DATA, "\0\0\0\0\0\0\0\0", 8, true);

	ctx->cur_file = NULL;
}

/* Needs to collect all the functions to call when we want to output coverage
 * data. (not really on exit)
 */
int atexit(atexit_fn_t* func)
{
	//kprintf("atexit(func = %p)\n", func);

	IOLockLock(state.lock);
	
	atexit_fn_t** fns = state.atexit_functions;
	uint32_t insert_at = state.exports_in_progress == 0 ? state.atexit_functions_first_null : state.atexit_functions_tail;
	if (insert_at >= state.atexit_functions_len)
	{
		uint32_t old_len = state.atexit_functions_len;
		uint64_t new_len = (old_len ?: 4) * UINT64_C(2);
		uint64_t new_size = new_len * sizeof(fns[0]);
		if (new_size > UINT32_MAX)
		{
			kprintf("atexit: New function pointer array would be too big (%llu bytes)\n", new_size);
			IOUnlock(state.lock);
			return 0;			
		}
		atexit_fn_t** new_fns = OSMalloc((uint32_t)new_size, state.tag);
		if (!new_fns)
		{
			kprintf("atexit: Failed to allocate function pointer array with %llu elements\n", new_len);
			IOUnlock(state.lock);
			return 0;
		}
		
		for (size_t fn_i = 0; fn_i < old_len; ++fn_i)
			new_fns[fn_i] = fns[fn_i];
		for (size_t fn_i = old_len; fn_i < new_len; ++fn_i)
			new_fns[fn_i] = NULL;
		
		if (fns)
			OSFree(fns, sizeof(fns[0]) * old_len, state.tag);
		state.atexit_functions = fns = new_fns;
		state.atexit_functions_len = (uint32_t)new_len;
	}
	
	assert(fns[insert_at] == NULL);
	fns[insert_at] = func;
	
	if (state.atexit_functions_tail <= insert_at)
		state.atexit_functions_tail = insert_at + 1;
	if (state.atexit_functions_first_null == insert_at)
		while(state.atexit_functions_first_null < state.atexit_functions_len && fns[state.atexit_functions_first_null] != NULL)
			++state.atexit_functions_first_null;
	
	//kprintf("atexit: added func %p at index %u\n", func, insert_at);
	
	IOUnlock(state.lock);
	
	return 0;
}

void llvm_gcov_init(writeout_fn_t wfn, flush_fn_t ffn)
{
	if (wfn == NULL && ffn == NULL)
		return;
	kext_cov_write_flush_t* new_el = kcov_alloc(kext_cov_write_flush_t, state.tag);
	if (!new_el)
	{
		kprintf("llvm_gcov_init: WARNING - failed to alloc kext_cov_write_flush_t entry for functions %p, %p\n", wfn, ffn);
		return;
	}
	new_el->writeout_fn = wfn;
	new_el->flush_fn = ffn;
	IOLockLock(state.lock);
	genc_slist_insert_at(&new_el->head, &state.write_flush_fns);
	IOLockUnlock(state.lock);
}


kern_return_t kext_cov_start(kmod_info_t* ki KCOV_UNUSED, void* d KCOV_UNUSED)
{
	state.tag = OSMalloc_Tagalloc("kext_cov", OSMT_DEFAULT);
	if (!state.tag)
		return KERN_RESOURCE_SHORTAGE;
	state.lock = IOLockAlloc();
	if (!state.lock)
	{
		OSMalloc_Tagfree(state.tag);
		state.tag = NULL;
		return KERN_RESOURCE_SHORTAGE;
	}

	int res = ctl_register(&ctl_reg, &state.ctl_ref);
	if (res != 0)
	{
		IOLockFree(state.lock);
		state.lock = NULL;
		OSMalloc_Tagfree(state.tag);
		state.tag = NULL;
		return KERN_RESOURCE_SHORTAGE;
	}
	kprintf("kext_cov_start: registered ctl: ctl_ref = %p\n", state.ctl_ref);
	
	return KERN_SUCCESS;
}

kern_return_t kext_cov_stop(kmod_info_t* ki KCOV_UNUSED, void* d KCOV_UNUSED)
{
	if (state.ctl_ref)
	{
		// this will disconnect all clients, which will also cancel all their threads
		int res = ctl_deregister(state.ctl_ref);
		if (res == EBUSY)
			return KERN_ABORTED;
		state.ctl_ref = NULL;
	}

	if (state.lock)
	{
		IOLockLock(state.lock);
		while (state.exports_in_progress > 0)
		{
			IOLockSleep(state.lock, &state.exports_in_progress, THREAD_UNINT);
		}
		IOLockUnlock(state.lock);
		IOLockFree(state.lock);
		state.lock = NULL;
	}
	if (state.tag)
		OSMalloc_Tagfree(state.tag);
	state.tag = NULL;
	
	kprintf("kext_cov_stop\n");
	return KERN_SUCCESS;
}

static void coverage_thread_main(void* arg, wait_result_t wait_result);

static errno_t kext_cov_connect(
	kern_ctl_ref kctlref,
	struct sockaddr_ctl* sac,
	void** unitinfo)
{
	kprintf("kext_cov_connect(kctlref = %p, sac = %p { len = %u, family = %u, sysaddr = %u, id = %u, unit = %u }, unitinfo = *%p (%p)\n",
		kctlref, sac,
		sac->sc_len, sac->sc_family, sac->ss_sysaddr, sac->sc_id, sac->sc_unit,
		unitinfo, *unitinfo);

	kext_cov_export_context_t* ctx = OSMalloc(sizeof(kext_cov_export_context_t), state.tag);
	if (!ctx)
		return ENOMEM;

	IOLockLock(state.lock);
	
	ctx->export_thread = NULL;
	
  ctx->ctl_ref = kctlref;
	ctx->unit = sac->sc_unit;

	ctx->cur_file = NULL;
	ctx->cur_packet = NULL;
	ctx->cur_packet_data = 0;
	ctx->cur_packet_type = 0;
	ctx->abort_export = false;
	
	kern_return_t res = kernel_thread_start(coverage_thread_main, ctx, &ctx->export_thread);
	if (res == KERN_SUCCESS)
	{
		genc_slist_insert_at(&ctx->context_list_head, &state.contexts);
		++state.exports_in_progress;	
	}
	else
	{
		OSFree(ctx, sizeof(kext_cov_export_context_t), state.tag);
	}
	IOLockUnlock(state.lock);
	
	*unitinfo = ctx;
	
	return res == KERN_SUCCESS ? 0 : ENOMEM;
}

static genc_bool_t identical_pred(struct slist_head* entry, void* data)
{
	return entry == data;
}


static errno_t kext_cov_disconnect(
	kern_ctl_ref kctlref KCOV_UNUSED,
	u_int32_t unit KCOV_UNUSED,
	void* unitinfo)
{
	kext_cov_export_context_t* ctx = unitinfo;
	if (ctx)
	{
		IOLockLock(state.lock);
		
		kext_cov_export_context_t* found = genc_slist_find_obj(
			state.contexts, kext_cov_export_context_t, context_list_head, identical_pred, &ctx->context_list_head);
		if (found)
		{
			// thread is still alive, tell it to stop ASAP
			ctx->abort_export = true;
		}
		
		IOLockUnlock(state.lock);
	}
	return 0;
}

static void compact_fns(struct kext_cov_state* st)
{
	assert(st->exports_in_progress == 0);
	atexit_fn_t** fns = st->atexit_functions;
	
	{
		uint32_t tail = st->atexit_functions_tail;
		while (tail > 0 && !fns[st->atexit_functions_tail - 1])
			--tail;
		st->atexit_functions_tail = tail;
	}
	
	while (st->atexit_functions_tail != st->atexit_functions_first_null)
	{
		assert(st->atexit_functions_tail > st->atexit_functions_first_null);
		uint32_t from = st->atexit_functions_tail - 1;
		uint32_t to = st->atexit_functions_first_null;
		assert(fns[from]);
		assert(!fns[to]);
		assert(from > to);
		fns[to] = fns[from];
		fns[from] = NULL;
		st->atexit_functions_tail = from;
		++to;
		while (fns[to] && to < from)
			++to;
		st->atexit_functions_first_null = to;
	}
}

static void coverage_thread_main(void* arg, wait_result_t wait_result)
{
	kext_cov_export_context_t* const ctx = arg;
	kprintf("coverage_thread_main(): wait_result = %d\n", wait_result);
	
	IOLockLock(state.lock);
	
	for (size_t fn_i = 0; fn_i < state.atexit_functions_tail && !ctx->abort_export; ++fn_i)
	{
		atexit_fn_t* fn = state.atexit_functions[fn_i];
		if (fn)
		{
			IOLockUnlock(state.lock);
			fn();
			IOLockLock(state.lock);
		}
	}
	
	kext_cov_write_flush_t* el;
	++state.write_flush_fns_walks_in_progress;
	genc_slist_for_each(el, state.write_flush_fns, kext_cov_write_flush_t, head)
	{
		writeout_fn_t fn = el->writeout_fn;
		if (fn)
		{
			IOLockUnlock(state.lock);
			fn();
			IOLockLock(state.lock);
		}
	}
	if (0 == --state.write_flush_fns_walks_in_progress)
	{
		IOLockWakeup(state.lock, &state.write_flush_fns_walks_in_progress, false /* wake all threads */);
	}
	
	// send the EOF packet if the client hasn't already gone away
	if (!ctx->abort_export)
	{
		append_packet_data(ctx, KCOV_PACKET_EOF, NULL, 0, true);
	}
	
	// remove self from global list
	--state.exports_in_progress;
	genc_slist_head_t** ref = genc_slist_find_ref(&ctx->context_list_head, &state.contexts);
	assert(ref);
	assert(*ref == &ctx->context_list_head);
	genc_slist_remove_at(ref);
	
	// tidy up
	if (state.exports_in_progress == 0)
		compact_fns(&state);
	if (ctx->cur_packet)
	{
		mbuf_freem(ctx->cur_packet);
		ctx->cur_packet = NULL;
	}	
	OSFree(ctx, sizeof(*ctx), state.tag);
	
	// If the kext is trying to unload, notify that waiting thread
	IOLockWakeup(state.lock, &state.exports_in_progress, true);
	
	IOLockUnlock(state.lock);
	
	kprintf("coverage_thread_main() done\n");
	thread_t thread = current_thread();
	thread_deallocate(thread);
	thread_terminate(thread);
}


void kext_cov_deregister_kext(kmod_info_t* kmod)
{
	IOLockLock(state.lock);
	
	while (state.write_flush_fns_walks_in_progress > 0)
	{
		IOLockSleep(state.lock, &state.write_flush_fns_walks_in_progress, THREAD_UNINT);
	}
	
	uint32_t num_dereg = 0;
	
	kext_cov_write_flush_t* wf;
	genc_slist_head_t** ref = &state.write_flush_fns;
	genc_slist_for_each_ref(wf, ref, kext_cov_write_flush_t, head)
	{
		uintptr_t fn_addr = (uintptr_t)(void*)wf->writeout_fn;
		if (fn_addr >= kmod->address && fn_addr < kmod->address + kmod->size)
		{
			genc_slist_remove_at(ref);
			OSFree(wf, sizeof(*wf), state.tag);
			++num_dereg;
		}
	}
	
	atexit_fn_t** fns = state.atexit_functions;
	for (uint32_t i = 0; i < state.atexit_functions_len; ++i)
	{
		if (fns[i] != NULL)
		{
			uintptr_t fn_addr = (uintptr_t)fns[i];
			if (fn_addr >= kmod->address && fn_addr < kmod->address + kmod->size)
			{
				/*
				kprintf("kext_cov_deregister_kext(): removed function %p (index %u) as it lies within kext %p range %lx-%lx\n",
					fns[i], i, kmod, kmod->address, kmod->address + kmod->size);
				*/
				fns[i] = NULL;
				if (i < state.atexit_functions_first_null)
					state.atexit_functions_first_null = i;
				++num_dereg;
			}
		}
	}
	
	if (state.exports_in_progress == 0)
		compact_fns(&state);
	
	IOLockUnlock(state.lock);
	kprintf("kext_cov_deregister_kext() deregistered %u functions from kext %.64s\n", num_dereg, kmod->name);
}

void llvm_gcda_increment_indirect_counter(const uint32_t* predecessor, uint64_t** counters)
{
	uint32_t pred = *predecessor;
	if (pred == 0xffffffffu)
		return;
	
	uint64_t* counter = counters[pred];
	if (!counter)
		return;
	__sync_fetch_and_add(counter, 1llu);
}


