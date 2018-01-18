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
#else
#include <Win32-Extensions.h>
#endif /*WIN32*/

#include "nio_jmemory.h"
#include "packet_jscanner.h"
#include "jnetpcap_utils.h"
#include "org_jnetpcap_winpcap_WinPcapSendQueue.h"
#include "export.h"


/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSendQueue
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcapSendQueue_sizeof
  (JNIEnv *env, jclass clazz) {
	
#ifdef WIN32
	return (jint) sizeof(pcap_send_queue);
	
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif

}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSendQueue
 * Method:    getLen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcapSendQueue_getLen
  (JNIEnv *env, jobject obj) {
	
#ifdef WIN32
	pcap_send_queue *q = (pcap_send_queue *)getJMemoryPhysical(env, obj);
	if (q == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "pcap_send_queue NULL");
		return -1;
	}
	
	return (jint) q->len;
	
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif

}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSendQueue
 * Method:    getMaxLen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcapSendQueue_getMaxLen
  (JNIEnv *env, jobject obj) {

#ifdef WIN32
pcap_send_queue *q = (pcap_send_queue *)getJMemoryPhysical(env, obj);
	if (q == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "pcap_send_queue NULL");
		return -1;
	}
	
	return (jint) q->maxlen;
	
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif


}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSendQueue
 * Method:    incLen
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcapSendQueue_incLen
  (JNIEnv *env, jobject obj, jint jdelta) {

#ifdef WIN32
pcap_send_queue *q = (pcap_send_queue *)getJMemoryPhysical(env, obj);
	if (q == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "pcap_send_queue NULL");
		return -1;
	}
	
	q->len += (int) jdelta;
	
	return (jint) q->len;
	
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif


}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSendQueue
 * Method:    setBuffer
 * Signature: (Lorg/jnetpcap/nio/JBuffer;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_winpcap_WinPcapSendQueue_setBuffer
  (JNIEnv *env, jobject obj, jobject jbuf) {
	
#ifdef WIN32
	pcap_send_queue *q = (pcap_send_queue *)getJMemoryPhysical(env, obj);
	if (q == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "pcap_send_queue NULL");
		return;
	}
	
	q->buffer = (char *)getJMemoryPhysical(env, jbuf);
	
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#endif

}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSendQueue
 * Method:    setLen
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_winpcap_WinPcapSendQueue_setLen
  (JNIEnv *env, jobject obj, jint jlen) {
#ifdef WIN32
	pcap_send_queue *q = (pcap_send_queue *)getJMemoryPhysical(env, obj);
	if (q == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "pcap_send_queue NULL");
		return;
	}
	
	q->len = (int) jlen;
	
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#endif


}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSendQueue
 * Method:    setMaxLen
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_winpcap_WinPcapSendQueue_setMaxLen
  (JNIEnv *env, jobject obj, jint jmaxlen) {
	
#ifdef WIN32
	pcap_send_queue *q = (pcap_send_queue *)getJMemoryPhysical(env, obj);
	if (q == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "pcap_send_queue NULL");
		return;
	}
	
	q->maxlen = (int) jmaxlen;
	
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#endif


}
