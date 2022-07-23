/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Main WinPcap extensions file for jNetPcap.
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

#include "winpcap_ext.h"
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"
#include "winpcap_ids.h"
#include "export.h"



/*
 * Function: new newWinPcapStat()
 * Description: allocates a new WinPcapStat object
 */
EXTERN jobject newWinPcapStat(JNIEnv *env) {
	if (WinPcapStatClass == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "Class ID not initialized");
		return NULL;
	}
	
	jobject jstats = env->NewObject(WinPcapStatClass, WinPcapStatConstructorMID);
	return jstats;
}

/*
 * Function: setWinPcapStat
 * Description: copies from pcap_stat structure all the members into a WinPcapStat
 *              object. Under MSDOS there are 21 fields within the structure.
 */
EXTERN void setWinPcapStat(JNIEnv *env, jobject jstats, 
		struct pcap_stat *stats, int size) {

#ifdef WIN32
	if (WinPcapStatClass == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "Class ID not initialized");
		return;
	}

	setPcapStat(env, jstats, stats); // Sets 1st 3
	
	if (size <= 12) {
		return;
	}
	env->SetLongField(jstats, pcapStatCaptFID, (jlong) stats->ps_capt);

	if (size <= 16) {
		return;
	}
	env->SetLongField(jstats, pcapStatSentFID, (jlong) stats->ps_sent);
	
	if (size <= 20) {
		return;
	}
	env->SetLongField(jstats, pcapStatNetdropFID, (jlong) stats->ps_netdrop);
#else
	 throwException(env, (const char*)PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, "");
	return;
#endif
}


