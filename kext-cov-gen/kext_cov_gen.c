//
//  main.c
//  kext-cov-gen
//
//  Created by Phillip Jordan on 05/12/2012.
//  Copyright (c) 2012-2014 Phil Jordan.
//
//  Released under the University of Illinois Open Source
//  License. See license.txt for details.


#include "../kext-cov/kext_cov_shared.h"
#include <stdio.h>
#include <sys/kernel_types.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>

static const int cmd = 1;

int main(int argc, const char* argv[])
{
	struct sockaddr_ctl       addr;
	int fd = -1;
	int result = 1;

	fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd != -1)
	{
		bzero(&addr, sizeof(addr)); // sets the sc_unit field to 0
		addr.sc_len = sizeof(addr);
		addr.sc_family = AF_SYSTEM;
		addr.ss_sysaddr = AF_SYS_CONTROL;

		{
			struct ctl_info info;
			memset(&info, 0, sizeof(info));
			strncpy(info.ctl_name, "com.ssdcache.kext-cov", sizeof(info.ctl_name));
			if (ioctl(fd, CTLIOCGINFO, &info)) {
				perror("Could not get ID for kernel control.\n");
				exit(-1);
			}
			addr.sc_id = info.ctl_id;
			addr.sc_unit = 0;
		}

		result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
		if (result) {
		 fprintf(stderr, "connect failed %d\n", result);
		}
	} else { /* no fd */
		fprintf(stderr, "failed to open socket\n");
	}

	if (!result)
	{
		/*result = setsockopt( fd, SYSPROTO_CONTROL, cmd, NULL, 0);
		if (result){
			fprintf(stderr, "setsockopt failed on kEPCommand1 call - result was %d\n", result);
			return 1;
		}*/
		
		FILE* f = NULL;
		ssize_t len;
		do
		{
			unsigned char buf[KEXT_COV_MAX_PACKET_SIZE];
			len = recv(fd, buf, KEXT_COV_MAX_PACKET_SIZE, 0);
			
			if (len < sizeof(struct kcov_packet_header))
			{
				printf("Bad data: len = %ld\n", len);
			}
			else
			{
				//printf("Header data (total %ld bytes): %02x %02x %02x %02x %02x\n", len, buf[0], buf[1], buf[2], buf[3], buf[4]);

				struct kcov_packet_header hdr;
				memcpy(&hdr, buf, sizeof(hdr));
				uint32_t pkt_len;
				memcpy(&pkt_len, hdr.packet_size_u32le, sizeof(pkt_len));
				
				if (pkt_len != len - sizeof(struct kcov_packet_header))
				{
					printf("Packet length (%ld) does not match header %u\n", len, pkt_len);
					if (pkt_len > len - sizeof(struct kcov_packet_header))
						pkt_len = (uint32_t)len - sizeof(struct kcov_packet_header);
				}
				
				if (hdr.packet_type == KCOV_PACKET_FILE_START)
				{
					if (f)
						fclose(f);
					char path[pkt_len + 1];
					memcpy(path, buf + sizeof(struct kcov_packet_header), pkt_len);
					path[pkt_len] = '\0';
					if (strlen(path) != pkt_len)
					{
						printf("Bad data: Path with nul characters - strlen reports %lu, path length supposedly %u\n", strlen(path), pkt_len);
					}
					
					const char* filename = strrchr(path, '/');
					if (filename)
						++filename;
					else
						filename = path;
					
					printf("New file: %s\n", filename);
					f = fopen(filename, "wb");
				}
				else if (hdr.packet_type == KCOV_PACKET_FILE_DATA)
				{
					//printf("%u bytes of payload data\n", pkt_len);
					fwrite(buf + sizeof(struct kcov_packet_header), pkt_len, 1, f);
				}
				else
				{
					if (hdr.packet_type != KCOV_PACKET_EOF)
						printf("Unexpected packet type: %02x\n", hdr.packet_type);
					printf("done\n");
					if (f)
						fclose(f);
					break;
				}
			}
			
			/*printf("received %ld bytes:\n", len);
			for (ssize_t i = 0; i < len; ++i)
			{
				if (i > 0)
				{
					if (i % 32 == 0)
						printf("\n");
					else if (i % 8 == 0)
						printf(" ");
				}
				printf("%02x ", buf[i]);
			}
			printf("\n");*/
		} while (len > 0);
	}
	return 0;
}

