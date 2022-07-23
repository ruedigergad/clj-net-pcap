/***************************************************************************
 * Copyright (C) 2017, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <jni.h>

#include "pcap_extension.h"

jint pcap_extension_dispatch_multi_packet_buffer(
		multipacket_buffer_state_t *state, jint cnt, jint descrLen);

/*
 * Class:     org_jnetpcap_extension_PcapExtension
 * Method:    peer
 * Signature: (Lorg/jnetpcap/Pcap;Lorg/jnetpcap/extension/PcapExtension;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_extension_PcapExtension_peer
(JNIEnv *env, jclass clazz, jobject pcapObject, jobject pcapExtensionObject) {

	pcap_t *pcap = getPcap(env, pcapObject);
	setPhysical(env, pcapExtensionObject, toLong(pcap));
}

/*
 * Class:     org_jnetpcap_extension_PcapExtension
 * Method:    dispatchToBuffer
 * Signature: (ILorg/jnetpcap/nio/JBuffer;III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_extension_PcapExtension_dispatchToBuffer
(JNIEnv *env, jobject obj, jint cnt, jobject jbuffer, jint capacity, jint off, jint descrLen) {

	if (jbuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "buffer");
		return -1;
	}

	pcap_t *pcap = getPcap(env, obj);
	if (pcap == NULL) {
		return -1;
	}

	multipacket_buffer_state_t state;
	memset(&state, 0, sizeof(state));

	state.pcap = pcap;
	state.off = off + sizeof(multipacket_buffer_counters_t);
	state.descrLen = descrLen;
	state.buffer_size = 1024 * 1024;
	state.buffer = (jbyte *)getJMemoryPhysical(env, jbuffer);
	state.counters = (multipacket_buffer_counters_t *) state.buffer; // Store counters in the array
	state.remaining = state.buffer_size - state.off;

	jbyte *buffer = (jbyte *)getJMemoryPhysical(env, jbuffer);
	if (buffer == NULL) {
		return -1;
	}

	jint result = pcap_extension_dispatch_multi_packet_buffer(&state, cnt, descrLen);

	return result;
}

/*
 * Class:     org_jnetpcap_extension_PcapExtension
 * Method:    dispatchToByteArray
 * Signature: (I[BII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_extension_PcapExtension_dispatchToByteArray
(JNIEnv *env, jobject obj, jint cnt, jbyteArray jarray, jint off, jint descrLen) {

	if (jarray == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "array");
		return -1;
	}

	pcap_t *pcap = getPcap(env, obj);
	if (pcap == NULL) {
		return -1;
	}

	jboolean isCopy = 0;
	multipacket_buffer_state_t state;
	memset(&state, 0, sizeof(state));

	state.pcap = pcap;
	state.off = off + sizeof(multipacket_buffer_counters_t);
	state.descrLen = descrLen;
	state.buffer_size = env->GetArrayLength(jarray);
	state.buffer = (jbyte *)env->GetPrimitiveArrayCritical(jarray, &isCopy);
	state.counters = (multipacket_buffer_counters_t *) state.buffer; // Store counters in the array
	state.remaining = state.buffer_size - state.off;

	if (state.buffer == NULL) {
		return -1; // Out of memory, when VM tried to make copy
	}

	if (off == 0) {
		memset(state.counters, 0, sizeof(multipacket_buffer_counters_t));
	}

	if (isCopy) {
		printf("DEBUG: AbstractJCapture_dispatchToByteArray: received a copy from GetPrimitiveArrayCritical!");
		fflush(stdout);
	}

	jint result = pcap_extension_dispatch_multi_packet_buffer(&state, cnt, descrLen);

	env->ReleasePrimitiveArrayCritical(jarray, state.buffer, 0);

	return result;
}

jint pcap_extension_dispatch_multi_packet_buffer(
		multipacket_buffer_state_t *state, jint cnt, jint descrLen) {

	multipacket_buffer_counters_t *counters = state->counters;

	jint dispatchedCnt = 0, result = 0, limitedCnt;
	const jint maxRecordLen = (MAX_PACKET_SIZE + descrLen);

	jint tries = 0;
//	printf(
//			"DEBUG: #%d PcapExtension_dispatchToByteArray: state[remaining=%ld, buffer=%p, off=%d, packets=%ld], isCopy=%d, result=%d\n",
//			tries ++, state.remaining, state.buffer, (int)state.off, state.counters->packetCount, isCopy, result);
//	fflush (stdout);

	/*
	 * Dispatch multiple times, with maximum number of packets that do not over fill
	 * buffer at maximum packet size. This way we allow the buffer to be filled
	 * to capacity without having to do complex multi-segment shuffling.
	 */
	do {

		if ((counters->flags & PCAP_EXTENSION_FLAG_BREAK_CAPTURE) != 0) {
			break;
		}

		limitedCnt = state->remaining / maxRecordLen;
		limitedCnt = (cnt != 0 && cnt < limitedCnt) ? cnt : limitedCnt;
		if (limitedCnt == 0) {
			break;
		}

		result = pcap_dispatch(state->pcap, limitedCnt,
				pcap_extension_callback_multi_packet_buffer, (u_char *) state);
		if (result > 0) {
			dispatchedCnt += result;
		}

		if (result < 0) {
			return result;
		}

//		printf(
//				"DEBUG: #%d PcapExtension_dispatchToByteArray: state[remaining=%ld, buffer=%p, off=%d, packets=%ld], isCopy=%d, result=%d\n",
//				tries ++, state.remaining, state.buffer, (int)state.off, state.counters->packetCount, isCopy, result);
//		fflush (stdout);

		/*
		 * If we captured limitedCnt packets, that means there are still more packets
		 * remaining in the pcap ring-buffer. Otherwise we drained the ring-buffer and
		 * there are no more packets, we can break out.
		 */
	} while (result == limitedCnt);

	pcap_stat mystat;
	/* Put the interface in statstics mode */
	if (pcap_stats(state->pcap, &mystat) == 0) {
		counters->packetDropCount = mystat.ps_drop + mystat.ps_ifdrop;
	}



	return dispatchedCnt;
}

void storePacketInBuffer(multipacket_buffer_state_t *state,
		const pcap_pkthdr *header, const u_char *data);

/*
 * PCAP prototype for callback method:
 *
 * typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
 */
void pcap_extension_callback_multi_packet_buffer(u_char *user,
		const pcap_pkthdr *header, const u_char *data) {

	multipacket_buffer_state_t *state = (multipacket_buffer_state_t *) user;

	storePacketInBuffer(state, header, data);
}

void storePacketInBuffer(multipacket_buffer_state_t *state,
		const pcap_pkthdr *header, const u_char *data) {
	multipacket_buffer_counters_t *counters = state->counters;

	jbyte *record = state->buffer + state->off;

	/* Copy header */
	memcpy(record + 0, header, sizeof(pcap_pkthdr));

	/* Copy packet data */
	memcpy(record + state->descrLen, data, (size_t) header->caplen);

	/* Padded record length (descr + packet + padding) */
	const jint recordLength = state->descrLen + header->caplen
	/*+ (8 - (state->off % 8))*/;

	/* Update offset into the buffer and bytes remaining */
	state->off += recordLength;
	state->remaining -= recordLength;

	/* Increment counters */
	counters->packetCount++;
	counters->bytesCount += recordLength;

}
