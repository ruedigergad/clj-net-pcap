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
#include "export.h"

/*******************************************************************************
 * Pcap.java IDs
 ******************************************************************************/
jclass pcapClass = NULL;
jclass stringBuilderClass = NULL;
jclass pcapIntegerClass = NULL;

jfieldID pcapPhysicalFID = 0;
jfieldID pcapIntegerValueFID = 0;

jmethodID pcapConstructorMID = 0;
jmethodID appendMID = 0;
jmethodID setLengthMID = 0;

jclass JBufferHandlerClass;
jclass ByteBufferHandlerClass;
jclass JPacketHandlerClass;
jclass PcapPacketHandlerClass;

jmethodID JBufferHandlerNextPacketMID;
jmethodID ByteBufferHandlerNextPacketMID;
jmethodID JPacketHandlerNextPacketMID;
jmethodID PcapPacketHandlerNextPacketMID;


/*
 * Class:     org_jnetpcap_Pcap
 * Method:    initIDs
 * Signature: ()V
 * Description: Initializes all of the jmethodID, jclass and jfieldIDs that are
 *              used by the entire collection of Pcap JNI related methods.
 *              This method only needs to be called once for all Pcap related
 *              classes. We do a lot of checks here and throw appropriate
 *              exceptions when something is not found. This is neccessary since
 *              no further runtime checks are performed after this initialization.
 */
JNIEXPORT void JNICALL JNICALL Java_org_jnetpcap_Pcap_initIDs
(JNIEnv *env, jclass clazz) {

	pcapClass = (jclass) env->NewGlobalRef(clazz); // This one is easy

	if ( (pcapConstructorMID = env->GetMethodID(clazz, 
			"<init>", "()V")) == NULL) {
		return;
	}

	if ( (pcapPhysicalFID = env->GetFieldID(clazz, "physical", "J")) == NULL) {
		return;
	}






	if ( (stringBuilderClass = findClass(env, 
			"java/lang/StringBuilder")) == NULL) {
		return;
	}

	if ( (appendMID = env->GetMethodID(stringBuilderClass, "append",
			"(Ljava/lang/String;)Ljava/lang/StringBuilder;")) == NULL) {
		return;
	}

	if ( (setLengthMID = env->GetMethodID(stringBuilderClass, "setLength",
			"(I)V")) == NULL) {
		return;
	}
	
	if ( (pcapIntegerClass = findClass(env, 
			"org/jnetpcap/PcapInteger")) == NULL) {
		return;
	}
	
	if ( (pcapIntegerValueFID = env->GetFieldID(pcapIntegerClass, "value",
			"I")) == NULL) {
		return;
	}
	
	if ( (JBufferHandlerClass = findClass(env, 
			"org/jnetpcap/JBufferHandler")) == NULL) {
		return;
	}

	if ( (ByteBufferHandlerClass = findClass(env, 
			"org/jnetpcap/ByteBufferHandler")) == NULL) {
		return;
	}
	if ( (JPacketHandlerClass = findClass(env, 
			"org/jnetpcap/packet/JPacketHandler")) == NULL) {
		return;
	}
	if ( (PcapPacketHandlerClass = findClass(env, 
			"org/jnetpcap/packet/PcapPacketHandler")) == NULL) {
		return;
	}

	if ( (JBufferHandlerNextPacketMID = 
		env->GetMethodID(JBufferHandlerClass, "nextPacket",
			"(Lorg/jnetpcap/PcapHeader;Lorg/jnetpcap/nio/JBuffer;Ljava/lang/Object;)V")) == NULL) {
		return;
	}
	if ( (ByteBufferHandlerNextPacketMID = 
		env->GetMethodID(ByteBufferHandlerClass, "nextPacket",
			"(Lorg/jnetpcap/PcapHeader;Ljava/nio/ByteBuffer;Ljava/lang/Object;)V")) == NULL) {
		return;
	}
	if ( (JPacketHandlerNextPacketMID = 
		env->GetMethodID(JPacketHandlerClass, "nextPacket",
			"(Lorg/jnetpcap/packet/JPacket;Ljava/lang/Object;)V")) == NULL) {
		return;
	}
	if ( (PcapPacketHandlerNextPacketMID = 
		env->GetMethodID(PcapPacketHandlerClass, "nextPacket",
			"(Lorg/jnetpcap/packet/PcapPacket;Ljava/lang/Object;)V")) == NULL) {
		return;
	}

}

/*******************************************************************************
 * PcapPktHdr.java IDs
 ******************************************************************************/
jfieldID PcapPktHdrSecondsFID = 0;
jfieldID PcapPktHdrUSecondsFID = 0;
jfieldID PcapPktHdrCaplenFID = 0;
jfieldID PcapPktHdrLenFID = 0;

jfieldID PcapPktBufferFID = 0;

/*
 * Class:     org_jnetpcap_PcapPktHdr
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapPktHdr_initIDs
(JNIEnv *env, jclass clazz) {
	jclass c;
	// PcapPktHdr class
	if ( (c = findClass(env, "org/jnetpcap/PcapPktHdr")) == NULL) {
		return;
	}

	if ( (PcapPktHdrSecondsFID = env->GetFieldID(c, "seconds", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPktHdr.seconds:long");
		return;
	}

	if ( (PcapPktHdrUSecondsFID = env->GetFieldID(c, "useconds", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPktHdr.useconds:int");
		return;
	}

	if ( (PcapPktHdrCaplenFID = env->GetFieldID(c, "caplen", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPktHdr.caplen:int");
		return;
	}

	if ( (PcapPktHdrLenFID = env->GetFieldID(c, "len", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPktHdr.len:int");
		return;
	}

	// PcapPktBuffer class
	if ( (c = findClass(env, "org/jnetpcap/PcapPktBuffer")) == NULL) {
		return;
	}

	if ( ( PcapPktBufferFID = env->GetFieldID(c, "buffer", "Ljava/nio/ByteBuffer;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPktBuffer.buffer:ByteBuffer");
		return;
	}


}

/*******************************************************************************
 * PcapAddr.java IDs
 ******************************************************************************/
jclass pcapAddrClass = NULL;
jfieldID pcapAddrNextFID = 0;
jfieldID pcapAddrAddrFID = 0;
jfieldID pcapAddrNetmaskFID = 0;
jfieldID pcapAddrBroadaddrFID = 0;
jfieldID pcapAddrDstaddrFID = 0;
jmethodID pcapAddrConstructorMID = 0;

/*
 * Class:     org_jnetpcap_PcapIf
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapAddr_initIDs
(JNIEnv *env, jclass clazz) {
	
	jclass c;
	// PcapAddr class
	if ( (pcapAddrClass = c = findClass(env, "org/jnetpcap/PcapAddr")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapAddr");
		return;
	}

	if ( (pcapAddrConstructorMID = env->GetMethodID(c, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor org.jnetpcap.PcapAddr()");
		return;
	}

	if ( ( pcapAddrNextFID = env->GetFieldID(c, "next", "Lorg/jnetpcap/PcapAddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.next:PcapAddr");
		return;
	}

	if ( ( pcapAddrAddrFID = env->GetFieldID(c, "addr", "Lorg/jnetpcap/PcapSockAddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.addr:PcapSockAddr");
		return;
	}

	if ( ( pcapAddrNetmaskFID = env->GetFieldID(c, "netmask", "Lorg/jnetpcap/PcapSockAddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.netmask:PcapSockAddr");
		return;
	}

	if ( ( pcapAddrBroadaddrFID = env->GetFieldID(c, "broadaddr", "Lorg/jnetpcap/PcapSockAddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.broadaddr:PcapSockAddr");
		return;
	}

	if ( ( pcapAddrDstaddrFID = env->GetFieldID(c, "dstaddr", "Lorg/jnetpcap/PcapSockAddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.dstaddr:PcapSockAddr");
		return;
	}
}
	
/*******************************************************************************
 * PcapIf.java IDs
 ******************************************************************************/
jclass pcapIfClass = NULL;
jfieldID pcapIfNextFID = 0;
jfieldID pcapIfNameFID = 0;
jfieldID pcapIfDescriptionFID = 0;
jfieldID pcapIfAddressesFID = 0;
jfieldID pcapIfFlagsFID = 0;jmethodID pcapIfConstructorMID = 0;

/*
 * Class:     org_jnetpcap_PcapIf
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapIf_initIDs
(JNIEnv *env, jclass clazz) {
	jclass c;
	// PcapIf class
	if ( (pcapIfClass = c = findClass(env, "org/jnetpcap/PcapIf")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapIf");
		return;
	}

	if ( (pcapIfConstructorMID = env->GetMethodID(c, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor org.jnetpcap.PcapIf()");
		return;
	}

	if ( ( pcapIfNextFID = env->GetFieldID(c, "next", "Lorg/jnetpcap/PcapIf;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.next:PcapIf");
		return;
	}

	if ( ( pcapIfNameFID = env->GetFieldID(c, "name", "Ljava/lang/String;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.name:String");
		return;
	}

	if ( ( pcapIfDescriptionFID = env->GetFieldID(c, "description", "Ljava/lang/String;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.description:String");
		return;
	}

	if ( ( pcapIfAddressesFID = env->GetFieldID(c, "addresses", "Ljava/util/List;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.addresses:List");
		return;
	}

	if ( ( pcapIfFlagsFID = env->GetFieldID(c, "flags", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.flags:int");
		return;
	}

}

/*******************************************************************************
 * PcapSockAddr.java IDs
 ******************************************************************************/
jclass PcapSockAddrClass = NULL;
jfieldID PcapSockAddrFamilyFID = 0;
jfieldID PcapSockAddrDataFID = 0;
jmethodID PcapSockAddrConstructorMID = 0;

/*
 * Class:     org_jnetpcap_PcapSockAddr
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapSockAddr_initIDs
(JNIEnv *env, jclass clazz) {
	jclass c;
	
	// PcapSockAddr class
	if ( (PcapSockAddrClass = c = findClass(env, "org/jnetpcap/PcapSockAddr")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapSockAddr");
		return;
	}

	if ( (PcapSockAddrConstructorMID = env->GetMethodID(c, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor org.jnetpcap.PcapSockAddr()");
		return;
	}

	if ( ( PcapSockAddrFamilyFID = env->GetFieldID(c, "family", "S")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapSockAddr.family:short");
		return;
	}

	if ( ( PcapSockAddrDataFID = env->GetFieldID(c, "data", "[B")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapSockAddr.data:byte[]");
		return;
	}

}

/*******************************************************************************
 * PcapStat.java IDs
 ******************************************************************************/

jclass pcapStatClass = NULL;

jfieldID pcapStatRecvFID = 0;
jfieldID pcapStatDropFID = 0;
jfieldID pcapStatIfDropFID = 0;

// These 3 are part of WinPcap, but they physically reside in PcapStat
jfieldID pcapStatCaptFID = 0;
jfieldID pcapStatSentFID = 0;
jfieldID pcapStatNetdropFID = 0;

/*
 * Class:     org_jnetpcap_PcapStat
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapStat_initIDs
(JNIEnv *env, jclass clazz) {

	pcapStatClass = (jclass) env->NewGlobalRef(clazz); // This one is easy

	if ( (pcapStatRecvFID = env->GetFieldID(clazz, "recv", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.recv:long");
		return;
	}

	if ( (pcapStatDropFID = env->GetFieldID(clazz, "drop", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.drop:long");
		return;
	}

	if ( (pcapStatIfDropFID = env->GetFieldID(clazz, "ifDrop", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.ifDrop:long");
		return;
	}

	if ( (pcapStatCaptFID = env->GetFieldID(clazz, "capt", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.capt:long");
		return;
	}
	
	if ( (pcapStatSentFID = env->GetFieldID(clazz, "sent", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.sent:long");
		return;
	}
	
	if ( (pcapStatNetdropFID = env->GetFieldID(clazz, "netdrop", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.netdrop:long");
		return;
	}
}

//jint JNI_OnLoad(JavaVM *vm, void *reserved) {
//	void *env;
//	if (vm->GetEnv(&env, JNI_VERSION_1_4) == JNI_EVERSION || env == NULL) {
//		printf("OnLoad FAILURE");
//		return JNI_VERSION_1_4;
//	}
//	
//	printf("OnLoad SUCCESS");
//	
//	return JNI_VERSION_1_1;
//}

