//
//  kext_cov_shared.h
//  kext-cov
//
//  Created by Phillip Jordan on 08/12/2012.
//  Copyright (c) 2012-2014 Phil Jordan. 
//  Released under the University of Illinois Open Source
//  License. See license.txt for details.
//
// Declarations/definitions shared between kernel and user space portions

#ifndef kext_cov_kext_cov_shared_h
#define kext_cov_kext_cov_shared_h

#include <stdint.h>

enum kext_cov_packet_type
{
	/// Starting new file, body data is file name
  KCOV_PACKET_FILE_START = 0x1,
	/// File payload data. Can have multiple such packets for each file
  KCOV_PACKET_FILE_DATA = 0x2,
	/// Done emitting file data (data length always 0)
	KCOV_PACKET_EOF = 0x3
};

struct kcov_packet_header
{
	uint8_t packet_type;
	uint8_t packet_size_u32le[4];
};

#define KEXT_COV_MAX_PACKET_SIZE 8192

#endif
