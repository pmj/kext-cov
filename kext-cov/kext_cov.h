//
//  kext_cov.h
//  kext-cov
//
//  Created by Phillip Jordan on 08/12/2012.
//  Copyright (c) 2012-2014 Phil Jordan.
//
//  Released under the University of Illinois Open Source
//  License. See license.txt for details.
//
// Public API, for use by other kexts

#ifndef kext_cov_kext_cov_h
#define kext_cov_kext_cov_h

#include <mach/kmod.h>

#ifdef __cplusplus
#define KCOV_CFUN extern "C"
#else
#define KCOV_CFUN extern
#endif

typedef void (*writeout_fn_t)(void);
typedef void (*flush_fn_t)(void);

/* Kexts which generate coverage information must call this function with their
 * kmod_info when unloading to avoid calls to its subsequently not existing
 * functions. */
KCOV_CFUN void kext_cov_deregister_kext(kmod_info_t* kmod);

// LLVM's coverage-data-generation we have to implement
KCOV_CFUN void llvm_gcda_start_file(const char* filename);
KCOV_CFUN void llvm_gcda_emit_function(uint32_t ident, const char* function_name);
KCOV_CFUN void llvm_gcda_emit_arcs(uint32_t num_counters, uint64_t* counters);
KCOV_CFUN void llvm_gcda_end_file(void);
// Substitute for atexit from Xcode 5.0 on
KCOV_CFUN void llvm_gcov_init(writeout_fn_t wfn, flush_fn_t ffn);

/***** START OBSOLETE *****/
// Functions no longer used by current versions of clang:

KCOV_CFUN void llvm_gcda_increment_indirect_counter(const uint32_t* predecessor, uint64_t** counters);

/* In a normal program, the export functions are registered for execution on
 * process exit. That makes no sense in the kernel, so we catch these function
 * registrations and call them upon request.
 */
KCOV_CFUN int atexit(void(*func)(void));
/***** END OBSOLETE *****/

#endif
