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
#include "org_jnetpcap_PcapHeader.h"
#include "export.h"


/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapHeader_sizeof
  (JNIEnv *env, jclass clazz) {
	
	return (jint) sizeof(pcap_pkthdr);
}

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_sec
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_PcapHeader_hdr_1sec__
  (JNIEnv *env, jobject obj) {
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, obj);
	if (hdr == NULL) {
		return -1;
	}

	return (jlong) hdr->ts.tv_sec;
}

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_sec
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapHeader_hdr_1sec__J
  (JNIEnv *env, jobject obj, jlong jts) {
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, obj);
	if (hdr == NULL) {
		return;
	}

	hdr->ts.tv_sec = (int) jts;
}

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_usec
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapHeader_hdr_1usec__
   (JNIEnv *env, jobject obj) {
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, obj);
	if (hdr == NULL) {
		return -1;
	}

	return (jlong) hdr->ts.tv_usec;
}

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_usec
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapHeader_hdr_1usec__I
   (JNIEnv *env, jobject obj, jint jts) {
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, obj);
	if (hdr == NULL) {
		return;
	}

	hdr->ts.tv_usec = (int) jts;
}

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_len
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapHeader_hdr_1len__
  (JNIEnv *env, jobject obj) {
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, obj);
	if (hdr == NULL) {
		return -1;
	}

	return (jlong) hdr->caplen;
}

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_len
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapHeader_hdr_1len__I
  (JNIEnv *env, jobject obj, jint jlen) {
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, obj);
	if (hdr == NULL) {
		return;
	}

	hdr->caplen = (int) jlen;
}

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_wirelen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapHeader_hdr_1wirelen__
  (JNIEnv *env, jobject obj) {
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, obj);
	if (hdr == NULL) {
		return -1;
	}

	return (jlong) hdr->len;
}

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_wirelen
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapHeader_hdr_1wirelen__I
  (JNIEnv *env, jobject obj, jint jlen) {
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, obj);
	if (hdr == NULL) {
		return;
	}

	hdr->len = (int) jlen;
}
