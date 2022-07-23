/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <jni.h>

#ifndef WIN32
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#endif /*WIN32*/

#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "packet_protocol.h"
#include "org_jnetpcap_util_checksum_Checksum.h"
#include "export.h"

#include "util_crc16.h"
#include "util_crc32.h"
#include "util_in_cksum.h"

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions.
 * 
 * **************************************************************
 ****************************************************************/


int in_checksum_pad_to_even(
		vec_t *vec,
		int veclen,
		pad_t *pad) {
	
	
	vec_t *last = &vec[veclen -1];
	
	if (last->len & 1) { // Odd length, needs padding
		pad->c[1] = 0;
		pad->c[0] = last->ptr[--last->len]; // Last byte is now in next vector
		
		vec[veclen].ptr = (const uint8_t *)pad;
		vec[veclen].len = 2;
		
		return 1;
	} else {
		return 0;
	}
}

int in_checksum_skip_crc16_field(
		const uint8_t *buf, // Buffer ptr
		vec_t *vec, 
		int len,
		int crc_offset) {   // 16-bit CRC field offset to skip
	
	vec[0].ptr = buf;
	vec[0].len = crc_offset;
	vec[1].ptr = (buf + (crc_offset + 2));
	vec[1].len = (len - (crc_offset + 2));
		
	return 2;
}

int in_checksum_add_ip_pseudo_header(
		const uint8_t *buf, 
		vec_t *vec, 
		int type, 
		int len,
		uint32_t phdr[]) {
		
	switch (*buf >> 4) {
	case 4:
		vec[0].ptr = (buf + 12);
		vec[0].len = 8;
		vec[1].len = 4;
		
		phdr[0] = BIG_ENDIAN32( (type << 16) | len);
		break;

	case 6:
		vec[0].ptr = (buf + 8);
		vec[0].len = 32;
		vec[1].len = 8;
		
		phdr[0] = BIG_ENDIAN32(len);
		phdr[1] = BIG_ENDIAN32(type);
		break;
	}
	
	vec[1].ptr = (const uint8_t *)phdr;
	
	return 2;
}

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/


/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    crc16CCITT
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_crc16CCITT
(JNIEnv *env, jclass clazz, jobject buf, jint offset, jint length) {

	jbyte *mem = (jbyte *)getJMemoryPhysical(env, buf);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size = (size_t) env->GetIntField(buf, jmemorySizeFID);
	if (offset < 0 || (offset + length)> (jint) size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	return (jint) crc16_ccitt(
			(const uint8_t *)(mem + offset),
			(uint32_t)length);
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    crc16CCITTSeed
 * Signature: (Lorg/jnetpcap/nio/JBuffer;III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_crc16CCITTSeed
(JNIEnv *env, jclass clazz, jobject buf, jint offset, jint length, jint seed) {

	jbyte *mem = (jbyte *)getJMemoryPhysical(env, buf);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size = (size_t) env->GetIntField(buf, jmemorySizeFID);
	if (offset < 0 || (offset + length)> (jint) size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	return (jint) crc16_ccitt_seed(
			(const uint8_t *)(mem + offset),
			(uint32_t)length,
			(uint32_t) seed);
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    crc16X25CCITT
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_crc16X25CCITT
(JNIEnv *env, jclass clazz, jobject buf, jint offset, jint length) {

	jbyte *mem = (jbyte *)getJMemoryPhysical(env, buf);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size = (size_t) env->GetIntField(buf, jmemorySizeFID);
	if (offset < 0 || (offset + length)> (jint) size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	return (jint) crc16_x25_ccitt(
			(const uint8_t *)(mem + offset),
			(uint32_t)length);
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    crc32CCITT
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_util_checksum_Checksum_crc32CCITT
(JNIEnv *env, jclass clazz, jobject buf, jint offset, jint length) {

	jbyte *mem = (jbyte *)getJMemoryPhysical(env, buf);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size = (size_t) env->GetIntField(buf, jmemorySizeFID);
	if (offset < 0 || (offset + length)> (jint) size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	return ((jlong) crc32_ccitt(
			(const uint8_t *)(mem + offset),
			(uint32_t)length)) & 0x00000000FFFFFFFFL;
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    crc32CCITTSeed
 * Signature: (Lorg/jnetpcap/nio/JBuffer;III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_crc32CCITTSeed
(JNIEnv *env, jclass clazz, jobject buf, jint offset, jint length, jint seed) {

	jbyte *mem = (jbyte *)getJMemoryPhysical(env, buf);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size = (size_t) env->GetIntField(buf, jmemorySizeFID);
	if (offset < 0 || (offset + length)> (jint) size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	return (jint) crc32_ccitt_seed(
			(const uint8_t *)(mem + offset),
			(uint32_t)length,
			(uint32_t) seed);
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    crc32IEEE802
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)J
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_crc32IEEE802
  (JNIEnv *env, jclass clazz, jobject buf, jint offset, jint length) {

	jlong c_crc = Java_org_jnetpcap_util_checksum_Checksum_crc32CCITT(
			env, clazz, buf, offset, length);

	/* Byte reverse. */
	c_crc = ((unsigned char)(c_crc>>0)<<24) |
		((unsigned char)(c_crc>>8)<<16) |
		((unsigned char)(c_crc>>16)<<8) |
		((unsigned char)(c_crc>>24)<<0);

	return (jint)c_crc & 0x00000000FFFFFFFFL;
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    crc32c
 * Signature: (Lorg/jnetpcap/nio/JBuffer;III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_crc32c
(JNIEnv *env, jclass clazz, jobject buf, jint offset, jint length, jint crc) {

	jbyte *mem = (jbyte *)getJMemoryPhysical(env, buf);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size = (size_t) env->GetIntField(buf, jmemorySizeFID);
	if (offset < 0 || (offset + length)> (jint) size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	return (jint) calculate_crc32c(
			(const uint8_t *)(mem + offset),
			(uint32_t)length,
			(uint32_t) crc);
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    inChecksumShouldBe
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_inChecksumShouldBe
  (JNIEnv *env, jclass clazz, jint checksum, jint calculated) {

	
	return (jint) in_cksum_shouldbe((uint16_t) checksum, (uint16_t) calculated);
}


/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    inChecksum
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_inChecksum
(JNIEnv *env, jclass clazz, jobject buf, jint offset, jint length) {

	uint8_t *mem = (uint8_t *)getJMemoryPhysical(env, buf);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size = (size_t) env->GetIntField(buf, jmemorySizeFID);
	if (offset < 0 || (offset + length)> (jint) size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	vec_t vec[] = {(mem + offset), length};

	return (jint) in_cksum(&vec[0], 1);
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    pseudoTcp
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_pseudoTcp
(JNIEnv *env, jclass clazz, jobject jbuf, jint ip, jint tcp) {
	
	const uint8_t *buf = (const uint8_t *)getJMemoryPhysical(env, jbuf);
	if (buf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}
	
	size_t size = (size_t) env->GetIntField(jbuf, jmemorySizeFID);
	if (ip < 0 || tcp < 0 || ip >= tcp || tcp >= size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	vec_t vec[5];
	uint32_t phdr[2];
	pad_t pad;
	int len;
	int is_padded;

	ip4_t *ip4 = (ip4_t *)(buf + ip);
	ip6_t *ip6;

	switch (IP4_GET_VER(ip4)) {
	case 4:
		len = IP4_GET_LEN(ip4) - IP4_CALC_LENGTH(ip4);
		break;
		
	case 6:
		ip6 = (ip6_t *)(buf + ip);	
		len = IP6_GET_PLEN(ip6) - (tcp - (ip + IP6_STRUCT_LENGTH));
		break;
		
	default:
		return (jint) -1;
	}
	
	if (ip + len > size) {
		return 0;
	}

	tcp_t *tcp_hdr = (tcp_t *)(buf + tcp);
	int hlen = TCP_CALC_LENGTH(tcp_hdr);
	if ((tcp + hlen) > size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}

	in_checksum_add_ip_pseudo_header(buf + ip, &vec[0], 6, len, phdr);
//	in_checksum_skip_crc16_field(buf + tcp, &vec[2], len, 16);	
	vec[2].ptr = (buf + tcp);
	vec[2].len = len;
	
	return (jint) in_cksum(vec, 3 + in_checksum_pad_to_even(vec, 3, &pad));
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    pseudoUdp
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_pseudoUdp
(JNIEnv *env, jclass clazz, jobject jbuf, jint ip, jint udp) {
	
	const uint8_t *buf = (const uint8_t *)getJMemoryPhysical(env, jbuf);
	if (buf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}
	
	size_t size = (size_t) env->GetIntField(jbuf, jmemorySizeFID);
	if (ip < 0 || udp < 0 || ip >= udp || udp >= size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}
	

	vec_t vec[5];
	uint32_t phdr[2];
	pad_t pad;
	int len;
	int is_padded;

	udp_t *pudp = (udp_t *)(buf + udp);
	len = UDP_GET_LENGTH(pudp);
	if (udp + len >= size) {
		return 0;
	}
	
	if ((udp + UDP_STRUCT_LENGTH) > size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}

	in_checksum_add_ip_pseudo_header(buf + ip, &vec[0], 17, len, phdr);
	vec[2].ptr = (buf + udp);
	vec[2].len = len;
	
	return (jint) in_cksum(vec, 3 + in_checksum_pad_to_even(vec, 3, &pad));
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    icmp
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_icmp
(JNIEnv *env, jclass clazz, jobject jbuf, jint ip, jint icmp) {
	
	const uint8_t *buf = (const uint8_t *)getJMemoryPhysical(env, jbuf);
	if (buf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}
	
	size_t size = (size_t) env->GetIntField(jbuf, jmemorySizeFID);
	if (ip < 0 || icmp < 0 || ip >= icmp || icmp >= size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	vec_t vec[5];
	uint32_t phdr[2];
	pad_t pad;
	int len;
	int is_padded;

	ip4_t *ip4 = (ip4_t *)(buf + ip);
	ip6_t *ip6;

	switch (IP4_GET_VER(ip4)) {
	case 4:
		len = IP4_GET_LEN(ip4) - IP4_CALC_LENGTH(ip4);
		break;
		
	case 6:
		ip6 = (ip6_t *)(buf + ip);	
		len = IP6_GET_PLEN(ip6) - (icmp - (ip + IP6_STRUCT_LENGTH));
		break;
		
	default:
		return (jint) -1;
	}
	
	if ((icmp + 4) > size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	if ((icmp + len) > size) {
		return 0;
	}

//	in_checksum_skip_crc16_field(buf + icmp, &vec[0], len, 2);
	vec[0].ptr = (buf + icmp);
	vec[0].len = len;
	
	return (jint) in_cksum(vec, 1 + in_checksum_pad_to_even(vec, 1, &pad));
}

/*
 * Class:     org_jnetpcap_util_checksum_Checksum
 * Method:    sctp
 * Signature: (Lorg/jnetpcap/nio/JBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_util_checksum_Checksum_sctp
  (JNIEnv *env, jclass clazz, jobject jbuf, jint sctpOffset, jint length) {

	const uint8_t *buf = (const uint8_t *)getJMemoryPhysical(env, jbuf);
	if (buf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size = (size_t) env->GetIntField(jbuf, jmemorySizeFID);
	if (sctpOffset < 0  || length + sctpOffset > size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}


#define CRC32_SCTP_SEED		0xFFFFFFFF
	int sum = calculate_crc32c(buf + sctpOffset, length, CRC32_SCTP_SEED);

	return ~sum;
}

