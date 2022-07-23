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

#include "jnetpcap_utils.h"
#include "org_jnetpcap_Pcap.h"
#include "export.h"


void pcap_jhandler_callback(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	pcap_user_data_t *data = (pcap_user_data_t *)user;

	JNIEnv *env = data->env;

	/**
	 * Check for pending exceptions
	 */
	if (env->ExceptionOccurred()) {
		return;
	}

	jobject buffer = env->NewDirectByteBuffer((void *)pkt_data,
			pkt_header->caplen);
	if (buffer == NULL) {
		env->DeleteLocalRef(buffer);
		return;
	}

	env->CallNonvirtualVoidMethod(data->obj, data->clazz, data->mid,
			(jobject) data->user, (jlong) pkt_header->ts.tv_sec,
			(jint)pkt_header->ts.tv_usec, (jint)pkt_header->caplen,
			(jint)pkt_header->len, buffer);
	
	env->DeleteLocalRef(buffer);
}

/**
 * =====================================================================
 */


/*
 * Class:     org_jnetpcap_PcapExperimental
 * Method:    dispatch
 * Signature: (ILorg/jnetpcap/JHandler;Ljava/lang/Object;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapExperimental_dispatch
  (JNIEnv *env, jobject obj, jint jcnt, jobject jhandler, jobject juser) {
	
	if (jhandler == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	/*
	 * Structure to encapsulate user data object, and store our JNI information
	 * so we can dispatch to Java land.
	 */
	pcap_user_data_t data;
	data.env = env;
	data.obj = jhandler;
	data.user = juser;
	data.clazz = env->GetObjectClass(jhandler);
	data.p = p;

	data.mid = env->GetMethodID(data.clazz, "nextPacket",
			"(Lorg/jnetpcap/PcapHeader;Lorg/jnetpcap/JBuffer;Ljava/lang/Object;)V");

	return pcap_dispatch(p, jcnt, pcap_jhandler_callback, (u_char *)&data);

}

/*
 * Class:     org_jnetpcap_PcapExperimental
 * Method:    loop
 * Signature: (ILorg/jnetpcap/JHandler;Ljava/lang/Object;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapExperimental_loop
  (JNIEnv *env, jobject obj, jint jcount, jobject jhandler, jobject juser) {
	
}

