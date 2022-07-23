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

#include "winpcap_stat_ex.h"
#include "jnetpcap_bpf.h"
#include "winpcap_ext.h"
#include "jnetpcap_utils.h"
#include "winpcap_ids.h"
#include "nio_jmemory.h"
#include "export.h"

jclass winPcapClass = 0;

jmethodID winPcapConstructorMID = 0;

/*
 * Function: testExtensionSupport
 * Description: Tests if WinPcap extensions is available on this platform.
 * Return: JNI_TRUE if yes, otherwise JNI_FALSE
 */
jboolean testExtensionSupport() {
#ifdef WIN32
	return (jboolean)JNI_TRUE;
#else
	return (jboolean)JNI_FALSE;
#endif
}

/*
 * Function: testExtensionSupportAndThrow
 * Description: checks if winpcap ext is supported and throws exception if not.
 * Return: JNI_TRUE if yes, otherwise JNI_FALSE
 */
jboolean testExtensionSupportAndThrow(JNIEnv *env) {

	if (testExtensionSupport() == JNI_FALSE) {
		throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, "");

		return JNI_FALSE;
	} else {
		return JNI_TRUE;
	}
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void Java_org_jnetpcap_winpcap_WinPcap_initIDs(JNIEnv *env,
		jclass jclazz) {
	winPcapClass = (jclass) env->NewGlobalRef(jclazz); // This one is easy

	/*
	 * Check if extensions are supported, if not, just quietly exit. Users
	 * must use WinPcap.isSupported() to check if extensions are availabe.
	 * Therefore we must let the WinPcap class finish loading normally, just
	 * left in uninitialized state. All static methods check and throw exception
	 * if not supported and called.
	 */
	if (testExtensionSupport() == JNI_FALSE) {
		return;
	}

	if ( (winPcapConstructorMID = env->GetMethodID(jclazz, "<init>", "()V"))
			== NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor WinPcap.WinPcap()");
		return;
	}

}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    isSupported
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_jnetpcap_winpcap_WinPcap_isSupported
(JNIEnv *env , jclass jclazz) {

	return testExtensionSupport();
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    openDead
 * Signature: (II)Lorg/jnetpcap/winpcap/WinPcap;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_winpcap_WinPcap_openDead
(JNIEnv *env, jclass clazz, jint jlinktype, jint jsnaplen) {

#ifdef WIN32

	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return NULL; // Exception already thrown
	}

	pcap_t *p = pcap_open_dead(jlinktype, jsnaplen);
	if (p == NULL) {
		return NULL;
	}

	/*
	 * Use a no-arg constructor and initialize 'physical' field using
	 * special JNI priviledges.
	 */
	jobject obj = env->NewObject(clazz, winPcapConstructorMID);
	setPhysical(env, obj, toLong(p));

	return obj;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    openLive
 * Signature: (Ljava/lang/String;IIILjava/lang/StringBuilder;)Lorg/jnetpcap/winpcap/WinPcap;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_winpcap_WinPcap_openLive
(JNIEnv *env, jclass clazz, jstring jdevice, jint jsnaplen, jint jpromisc, jint jtimeout,
		jobject jerrbuf) {

#ifdef WIN32
	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return NULL; // Exception already thrown
	}

	if (jdevice == NULL || jerrbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = '\0'; // Reset the buffer;

	const char *device = env->GetStringUTFChars(jdevice, 0);

	//	printf("device=%s snaplen=%d, promisc=%d timeout=%d\n",
	//			device, jsnaplen, jpromisc, jtimeout);

	pcap_t *p = pcap_open_live(device, jsnaplen, jpromisc, jtimeout, errbuf);
	setString(env, jerrbuf, errbuf); // Even if no error, could have warning msg
	env->ReleaseStringUTFChars(jdevice, device);
	if (p == NULL) {
		return NULL;
	}

	/*
	 * Use a no-arg constructor and initialize 'physical' field using
	 * special JNI priviledges.
	 */
	jobject obj = env->NewObject(clazz, winPcapConstructorMID);
	setPhysical(env, obj, toLong(p));

	return obj;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    openOffline
 * Signature: (Ljava/lang/String;Ljava/lang/StringBuilder;)Lorg/jnetpcap/winpcap/WinPcap;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_winpcap_WinPcap_openOffline
(JNIEnv *env, jclass clazz, jstring jfname, jobject jerrbuf) {

#ifdef WIN32
	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return NULL; // Exception already thrown
	}

	if (jfname == NULL || jerrbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = '\0'; // Reset the buffer;
	const char *fname = env->GetStringUTFChars(jfname, 0);

	pcap_t *p = pcap_open_offline(fname, errbuf);
	setString(env, jerrbuf, errbuf);

	env->ReleaseStringUTFChars(jfname, fname);

	if (p == NULL) {
		return NULL;
	}

	/*
	 * Use a no-arg constructor and initialize 'physical' field using
	 * special JNI priviledges.
	 */
	jobject obj = env->NewObject(clazz, winPcapConstructorMID);
	setPhysical(env, obj, toLong(p));

	return obj;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    setBuff
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_setBuff
(JNIEnv *env, jobject obj, jint value) {

#ifdef WIN32
	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	return pcap_setbuff(p, value);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}
/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    setMode
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_setMode
(JNIEnv *env, jobject obj, jint value) {

#ifdef WIN32
	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	return pcap_setmode(p, value);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    setMinToCopy
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_setMinToCopy
(JNIEnv *env, jclass obj, jint jminsize) {

#ifdef WIN32
	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	return pcap_setmintocopy(p, (int)jminsize);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -2;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    offlineFilter
 * Signature: (Lorg/jnetpcap/PcapBpfProgram;I;I;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_offlineFilter__Lorg_jnetpcap_PcapBpfProgram_2IILjava_nio_ByteBuffer_2
(JNIEnv *env, jclass clazz, jobject jbpf, jint caplen, jint len, jobject jbuf) {

#ifdef WIN32
	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return -1; // Exception already thrown
	}

	if (jbpf == NULL || jbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	bpf_program *bpf = getBpfProgram(env, jbpf);
	if (bpf == NULL) {
		return -1; // Exception already thrown
	}

	pcap_pkthdr hdr;
	hdr.len = (int)len;
	hdr.caplen = (int)caplen;

	u_char *b = (u_char *)env->GetDirectBufferAddress(jbuf);
	if (b == NULL) {
		return -1; // Exception already thrown
	}

	return (jint) pcap_offline_filter (bpf, &hdr, b);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}


/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    offlineFilter
 * Signature: (Lorg/jnetpcap/PcapBpfProgram;Lorg/jnetpcap/PcapPktHdr;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_offlineFilter__Lorg_jnetpcap_PcapBpfProgram_2Lorg_jnetpcap_PcapPktHdr_2Ljava_nio_ByteBuffer_2
(JNIEnv *env, jclass clazz, jobject jbpf, jobject jhdr, jobject jbuf) {

#ifdef WIN32
	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return -1; // Exception already thrown
	}

	if (jbpf == NULL || jhdr == NULL || jbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	bpf_program *bpf = getBpfProgram(env, jbpf);
	if (bpf == NULL) {
		return -1; // Exception already thrown
	}

	pcap_pkthdr hdr;
	getPktHeader(env, jhdr, &hdr);

	u_char *b = (u_char *)env->GetDirectBufferAddress(jbuf);
	if (b == NULL) {
		return -1; // Exception already thrown
	}

	return (jint) pcap_offline_filter (bpf, &hdr, b);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    offlineFilter
 * Signature: (Lorg/jnetpcap/PcapBpfProgram;Lorg/jnetpcap/PcapHeader;Lorg/jnetpcap/nio/JBuffer;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_offlineFilter__Lorg_jnetpcap_PcapBpfProgram_2Lorg_jnetpcap_PcapHeader_2Lorg_jnetpcap_nio_JBuffer_2
(JNIEnv *env, jclass clazz, jobject jbpf, jobject jhdr, jobject jbuf) {

#ifdef WIN32
	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return -1; // Exception already thrown
	}

	if (jbpf == NULL || jhdr == NULL || jbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	bpf_program *bpf = getBpfProgram(env, jbpf);
	if (bpf == NULL) {
		return -1; // Exception already thrown
	}

	pcap_pkthdr *hdr;
	hdr = (pcap_pkthdr *)getJMemoryPhysical(env, jhdr);

	u_char *b = (u_char *)getJMemoryPhysical(env, jbuf);
	if (b == NULL) {
		return -1; // Exception already thrown
	}

	return (jint) pcap_offline_filter (bpf, hdr, b);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    liveDump
 * Signature: (Ljava/lang/String;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_liveDump
(JNIEnv *env, jobject obj, jstring jfname, jint jmaxsize, jint jmaxpackets) {

#ifdef WIN32
	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	char *fname = (char *)env->GetStringUTFChars(jfname, 0);
	if (fname == NULL) {
		return -1; // Out of memory
	}

	int r = pcap_live_dump(p, fname, (int) jmaxsize, (int) jmaxpackets);

	env->ReleaseStringUTFChars(jfname, fname);

	return r;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    liveDumpEnded
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_liveDumpEnded
(JNIEnv *env, jobject obj, jint jsync) {

#ifdef WIN32
	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	return pcap_live_dump_ended(p, (int) jsync);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    statsEx
 * Signature: ()Lorg/jnetpcap/winpcap/PcapStatEx;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_winpcap_WinPcap_statsEx
(JNIEnv *env, jobject obj) {

#ifdef WIN32
	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return NULL; // Exception already thrown
	}

	struct pcap_stat *stats;
	int size = 0;
	stats = (struct pcap_stat *)pcap_stats_ex(p, &size); // Fills the stats structure
	if (stats == NULL) {
		return NULL; // error
	}

	jobject jstats = newWinPcapStat(env);
	if (jstats == NULL) {
		return NULL;
	}

	struct pcap_stat ps;
	ps.ps_netdrop = 0;

	setWinPcapStat(env, jstats, stats, size);

	free(stats); // release the memory

	return jstats;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    sendQueueTransmitPrivate
 * Signature: (Ljava/nio/ByteBuffer;III)I
 */
JNIEXPORT jint
JNICALL Java_org_jnetpcap_winpcap_WinPcap_sendQueueTransmitPrivate
(JNIEnv *env, jobject obj, jobject jbuf, jint jlen, jint jmaxlen, jint jsync) {

#ifdef WIN32
	if (jbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	char *buffer = (char *)env->GetDirectBufferAddress(jbuf);
	if (buffer == NULL) {
		throwException(env, ILLEGAL_ARGUMENT_EXCEPTION,
				"Invalid buffer, can not retrieve physical address. "
				"Must be a direct buffer.");
		return -1;
	}

	pcap_send_queue queue;
	queue.len = (int) jlen;
	queue.maxlen = (int) jmaxlen;
	queue.buffer = buffer;

	return pcap_sendqueue_transmit(p, &queue, (int)jsync);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    sendQueueTransmit
 * Signature: (Lorg/jnetpcap/winpcap/WinPcapSendQueue;I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_sendQueueTransmit
  (JNIEnv *env, jobject obj, jobject jqueue, jint jsync) {

#ifdef WIN32
	if (jqueue == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	pcap_send_queue *queue = (pcap_send_queue *)getJMemoryPhysical(env, jqueue);
	
	return pcap_sendqueue_transmit(p, queue, (int)jsync);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}



#ifdef WIN32
/*
 * Function: newWinPcapSamp
 * Description: create a new instance of WinPcapSamp class
 */
jobject newWinPcapSamp(JNIEnv *env, pcap_samp *samp) {

	long addr = toLong(samp);
	jobject jsamp = env->NewObject(winPcapSampClass, winPcapSampConstructorMID,
			(jlong) addr);

	return jsamp;
}
#endif

#ifdef WIN32
/*
 * Function: getWinPcapSamp
 * Description: gets the pcap_samp structure from PcapWinSamp object
 *              or thrown an exception if not initialized
 */
pcap_samp *getWinPcapSamp(JNIEnv *env, jobject obj) {

	long addr = (long) env->GetLongField(obj, winPcapSampPhysicalFID);

	if (addr == 0) {
		throwException(env, ILLEGAL_STATE_EXCEPTION,
				"WinPcapSamp object not initialized properly. "
					"Physical address is null.");
		return NULL;
	}

	return (pcap_samp *) toPtr(addr);
}
#endif

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSamp
 * Method:    getMethod
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcapSamp_getMethod
(JNIEnv *env, jobject obj) {

#ifdef WIN32
	pcap_samp *samp = getWinPcapSamp(env, obj);
	if (samp == NULL) {
		return -1; // Exception already thrown
	}

	return (jint) samp->method;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSamp
 * Method:    setMethod
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_winpcap_WinPcapSamp_setMethod
(JNIEnv *env, jobject obj, jint jmethod) {

#ifdef WIN32
	pcap_samp *samp = getWinPcapSamp(env, obj);
	if (samp == NULL) {
		return; // Exception already thrown
	}

	samp->method = (int) jmethod;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSamp
 * Method:    getValue
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcapSamp_getValue
(JNIEnv *env, jobject obj) {

#ifdef WIN32
	pcap_samp *samp = getWinPcapSamp(env, obj);
	if (samp == NULL) {
		return -1; // Exception already thrown
	}

	return (jint) samp->value;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcapSamp
 * Method:    setValue
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_winpcap_WinPcapSamp_setValue
(JNIEnv *env, jobject obj, jint jvalue) {

#ifdef WIN32
	pcap_samp *samp = getWinPcapSamp(env, obj);
	if (samp == NULL) {
		return; // Exception already thrown
	}

	samp->value = (int) jvalue;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    setSampling
 * Signature: ()Lorg/jnetpcap/winpcap/WinPcapSamp;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_winpcap_WinPcap_setSampling
(JNIEnv *env, jobject obj) {

#ifdef WIN32
	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return NULL; // Exception already thrown
	}

	pcap_samp *samp = pcap_setsampling(p);
	if (samp == NULL) {
		return NULL; // Method supported only on live captures, not on savefiles
	}

	return newWinPcapSamp(env, samp);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif
}

#ifdef WIN32
/*
 * Function: getWinPcapRmtAuth
 * Description: reads and returns pcap_rmtauth structure from java object
 *              If auth is null, it will be allocated, otherwise its just filled
 *              in.
 */
pcap_rmtauth *getWinPcapRmtAuth(JNIEnv *env, jobject jauth, pcap_rmtauth *auth) {

	if (jauth == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "jauth is null");
		return NULL;
	}

	if (auth == NULL) {
		auth = (pcap_rmtauth *) malloc(sizeof(pcap_rmtauth));
	}

	jstring jusername = (jstring) env->GetObjectField(jauth,
			winPcapRmtAuthUsernameFID);
	jstring jpassword = (jstring) env->GetObjectField(jauth,
			winPcapRmtAuthPasswordFID);

	if (jusername != NULL) {
		auth->username = (char *)env->GetStringUTFChars(jusername, 0);
		env->ReleaseStringUTFChars(jusername, auth->username);
	}

	if (jpassword != NULL) {
		auth->password = (char *)env->GetStringUTFChars(jpassword, 0);
		env->ReleaseStringUTFChars(jpassword, auth->password);
	}

	auth->type = (int) env->GetIntField(jauth, winPcapRmtAuthTypeFID);

	return auth;
}
#endif

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    findAllDevsEx
 * Signature: (Ljava/lang/String;Lorg/jnetpcap/winpcap/WinPcapRmtAuth;Ljava/util/List;Ljava/lang/StringBuilder;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_findAllDevsEx
(JNIEnv *env, jclass clazz, jstring jsource, jobject jauth, jobject jlist,
		jobject jerrbuf) {

#ifdef WIN32
	if (jlist == NULL || jerrbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = '\0'; // Reset the buffer;

	pcap_rmtauth buf;
	pcap_rmtauth *auth = (jauth != NULL)?getWinPcapRmtAuth(env, jauth, &buf):NULL;

	char *source = (char *) env->GetStringUTFChars(jsource, 0);

	pcap_if_t *alldevsp;

	int r = pcap_findalldevs_ex(source, auth, &alldevsp, errbuf);

	env->ReleaseStringUTFChars(jsource, source);

	if (r != 0) {
		setString(env, jerrbuf, errbuf);
		return r;
	}

	if (alldevsp != NULL) {
		jmethodID MID_add = findMethod(env, jlist, "add",
				"(Ljava/lang/Object;)Z");

		jobject jpcapif = newPcapIf(env, jlist, MID_add, alldevsp);
		if (jpcapif == NULL) {
			return -1; // Out of memory
		}

		if (env->CallBooleanMethod(jlist, MID_add, jpcapif) == JNI_FALSE) {
			env->DeleteLocalRef(jpcapif);

			return -1; // Failed to add to the list
		}

		env->DeleteLocalRef(jpcapif);

		return r;
	}

	/*
	 * The device list is freed up, since we copied all the info into Java
	 * objects that are no longer dependent on native C classes.
	 */
	pcap_freealldevs(alldevsp);

	return r;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif

}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    open
 * Signature: (Ljava/lang/String;IIILorg/jnetpcap/winpcap/WinPcapRmtAuth;Ljava/lang/StringBuilder;)Lorg/jnetpcap/winpcap/WinPcap;
 */
JNIEXPORT jobject JNICALL
Java_org_jnetpcap_winpcap_WinPcap_open
(JNIEnv *env, jclass clazz, jstring jsource, jint jsnaplen, jint jflags,
		jint jtimeout, jobject jauth, jobject jerrbuf) {

#ifdef WIN32
	if (jsource == NULL || jerrbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = '\0'; // Reset the buffer;

	char *source = (char *) env->GetStringUTFChars(jsource, 0);

#ifndef DONT_FIX_WINPCAP_BUGS
	/*
	 * 2007-08-09 - Mark Bednarczyk
	 * There is a bug in WinPcap where flags | 8 == 8 or flag | 16 == 16 and the 
	 * device name is wrong (pcap_open_live would fail), wpdpack doesn't catch 
	 * it and crashes. We need to test for valid device name for IFLOCAL type 
	 * ourselves.
	 */
	char host[PCAP_BUF_SIZE], port[PCAP_BUF_SIZE], name[PCAP_BUF_SIZE];
	int type = 0;
	if (pcap_parsesrcstr(source, &type, host, port, name, errbuf) == -1) {
		setString(env, jerrbuf, errbuf); // Even if no error, could have warning msg
		return NULL; // error already set in errbuf
	}

	if (type == PCAP_SRC_IFLOCAL) {
		int flags = (int) jflags;
		pcap_t *temp = pcap_open_live(
				name,
				(int) jsnaplen,
				(flags & PCAP_OPENFLAG_PROMISCUOUS),
				(int) jtimeout,
				errbuf);

		if (temp == NULL) {
			env->ReleaseStringUTFChars(jsource, source);
			setString(env, jerrbuf, errbuf); // Even if no error, could have warning msg
			return NULL; // error already set in errbuf
		} else {
			pcap_close(temp); // Close it, and let the call pass through
		}
	}
#endif

	pcap_rmtauth buf;
	pcap_rmtauth *auth = (jauth != NULL)?getWinPcapRmtAuth(env, jauth, &buf):NULL;

	pcap_t * p = pcap_open(source, (int)jsnaplen, (int) jflags, (int) jtimeout,
			auth, errbuf);
	setString(env, jerrbuf, errbuf); // Even if no error, could have warning msg
	env->ReleaseStringUTFChars(jsource, source);

	if (p == NULL) {
		return NULL;
	}

	/*
	 * Use a no-arg constructor and initialize 'physical' field using
	 * special JNI priviledges.
	 */
	jobject obj = env->NewObject(clazz, winPcapConstructorMID);
	if (obj == NULL) {
		return NULL; // OutOfMemory exception already thrown.
	}
	setPhysical(env, obj, toLong(p));

	return obj;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    createSrcStr
 * Signature: (Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_createSrcStr
(JNIEnv *env, jclass clazz, jobject jsource, jint jtype, jstring jhost,
		jstring jport, jstring jname, jobject jerrbuf) {

#ifdef WIN32
	if (jsource == NULL || jerrbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = '\0'; // Reset the buffer;

	char source[PCAP_BUF_SIZE];
	source[0] = '\0'; // Reset the buffer;

	const char *host = (jhost == NULL)?NULL:env->GetStringUTFChars(jhost, 0);
	const char *port = (jport == NULL)?NULL:env->GetStringUTFChars(jport, 0);
	const char *name = (jname == NULL)?NULL:env->GetStringUTFChars(jname, 0);

	int r = pcap_createsrcstr(source, (int) jtype, host, port, name, errbuf);
	setString(env, jerrbuf, errbuf); // Even if no error, could have warning msg

	env->ReleaseStringUTFChars(jhost, host);
	env->ReleaseStringUTFChars(jport, port);
	env->ReleaseStringUTFChars(jname, name);

	if (r != 0) {
		return r;
	}

	setString(env, jsource, source);

	return r;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

