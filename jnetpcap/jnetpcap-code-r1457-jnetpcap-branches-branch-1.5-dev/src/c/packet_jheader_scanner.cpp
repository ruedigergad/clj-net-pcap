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
#include "packet_jscanner.h"
#include "jnetpcap_utils.h"
#include "org_jnetpcap_packet_JHeaderScanner.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_packet_JHeaderScanner
 * Method:    bindNativeScanner
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JHeaderScanner_bindNativeScanner
(JNIEnv *env, jobject obj, jint id) {

	if (id < 0 || id > MAX_ID_COUNT) {
		sprintf(str_buf, "invalid ID=%d (%s)", id, id2str(id));
		throwException(env, UNREGISTERED_SCANNER_EXCEPTION, str_buf);
		return;
	}

	if (native_protocols[id] == NULL) {
		
		sprintf(str_buf, "native scanner not registered under ID=%d (%s)", 
				id,
				id2str(id));
		throwException(env, UNREGISTERED_SCANNER_EXCEPTION,	str_buf);
		return;
	}

	setJMemoryPhysical(env, obj, toLong((void *)native_protocols[id]));
}

/*
 * Class:     org_jnetpcap_packet_JHeaderScanner
 * Method:    nativeScan
 * Signature: (Lorg/jnetpcap/packet/JScan;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JHeaderScanner_nativeScan
(JNIEnv *env, jobject obj, jobject jscan) {

	native_protocol_func_t func = (native_protocol_func_t)getJMemoryPhysical(env, obj);
	if (func == NULL) {
		return;
	}

	scan_t *scan = (scan_t *)getJMemoryPhysical(env, jscan);
	if (jscan == NULL) {
		return;
	}

	// Dispatch to function pointer
	func(scan);
}

