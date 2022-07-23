/* Header for jnetpcap_utils utility methods */

#ifndef _Included_pcap_extension_h
#define _Included_pcap_extension_h
#ifdef __cplusplus

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <jni.h>

#include "nio_jmemory.h"
#include "nio_jbuffer.h"
#include "packet_jscanner.h"
#include "jnetpcap_utils.h"
#include "export.h"

#define MAX_PACKET_SIZE	1524

#define PCAP_EXTENSION_FLAG_BREAK_CAPTURE	0x0001

void pcap_extension_callback_multi_packet_buffer(u_char*, const pcap_pkthdr*,
		const u_char*);

typedef struct multipacket_buffer_counters_s {

	// #0
	jlong flags;

	// #8
	jlong packetCount;

	// #16
	jlong bytesCount;

	// #24
	jlong packetDropCount;

	// #32
	jlong bytesDropCount;

	jlong reserved1;

	jlong reserved2;

	jlong reserved3;

} multipacket_buffer_counters_t;

typedef struct multipacket_buffer_state_s {

	multipacket_buffer_counters_t *counters;
	jbyte *buffer;

	size_t buffer_size;
	size_t remaining;
	jint off;
	jint descrLen;

	pcap_t *pcap;
	pcap_stat pcap_statistics;

} multipacket_buffer_state_t;

#endif
#endif
