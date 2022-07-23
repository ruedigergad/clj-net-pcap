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
#include "export.h"

#include "jnetpcap_utils.h"

/*******************************************************************************
 * WinPcapSamp.java IDs
 ******************************************************************************/
jclass winPcapSampClass = NULL;

jmethodID winPcapSampConstructorMID = 0;
jfieldID winPcapSampPhysicalFID = 0;

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSamp
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_winpcap_WinPcapSamp_initIDs
(JNIEnv *env, jclass clazz) {

	if (winPcapSampClass != NULL) {
		env->DeleteGlobalRef(winPcapSampClass);
	}

	jclass c = winPcapSampClass = (jclass) env->NewGlobalRef(clazz);

	if ( (winPcapSampPhysicalFID = env->GetFieldID(c, "physical", "J")) == 0) {
		return;
	}
	
	if ( (winPcapSampConstructorMID = env->GetMethodID(c, "<init>", "(J)V")) == 0) {
		return;
	}
}

/*******************************************************************************
 * WinPcapSamp.java IDs
 ******************************************************************************/
jclass WinPcapStatClass = 0;

jmethodID WinPcapStatConstructorMID = 0;

/*
 * Class:     org_jnetpcap_winpcap_WinPcapStat
 * Method:    initIDs
 * Signature: ()V
 */
EXTERN void JNICALL Java_org_jnetpcap_winpcap_WinPcapStat_initIDs
(JNIEnv *env, jclass clazz) {

	if (WinPcapStatClass != NULL) {
		env->DeleteGlobalRef(WinPcapStatClass);
	}

	WinPcapStatClass = (jclass) env->NewGlobalRef(clazz);
	if ( (WinPcapStatConstructorMID = env->GetMethodID(clazz, "<init>", "()V")) == 0) {
		return;
	}
}


/*******************************************************************************
 * WinPcapRmtAuth.java IDs
 ******************************************************************************/
jclass winPcapRmtAuthClass = NULL;

jfieldID winPcapRmtAuthTypeFID = 0;
jfieldID winPcapRmtAuthUsernameFID = 0;
jfieldID winPcapRmtAuthPasswordFID = 0;



/*
 * Class:     org_jnetpcap_winpcap_WinPcapRmtAuth
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_winpcap_WinPcapRmtAuth_initIDs
  (JNIEnv *env , jclass clazz) {
	
	if (winPcapRmtAuthClass != NULL) {
		env->DeleteGlobalRef(WinPcapStatClass);
	}

	winPcapRmtAuthClass = (jclass) env->NewGlobalRef(clazz);
	
	if ( (winPcapRmtAuthTypeFID = env->GetFieldID(clazz, "type", "I")) == 0) {
		return;
	}

	if ( (winPcapRmtAuthUsernameFID = env->GetFieldID(clazz, "username", 
			"Ljava/lang/String;")) == 0) {
		return;
	}
	
	if ( (winPcapRmtAuthPasswordFID = env->GetFieldID(clazz, "password", 
			"Ljava/lang/String;")) == 0) {
		return;
	}
}
