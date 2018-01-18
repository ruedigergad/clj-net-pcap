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
#include "org_jnetpcap_packet_JPacket_State.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/
/*
 * finds a specific header instance
 */
jint findHeaderById(packet_state_t *packet, jint id, jint instance) {
//	printf("findHeaderIndex(%d, %d)\n", id, instance);
//	fflush(stdout);
	
//	if (packet->pkt_instance_counts[id] < instance) {
//		return -1;
//	}
	
	for (int i = 0; i < packet->pkt_header_count; i ++ ) {
		header_t *header = &packet->pkt_headers[i];
		
		if (header->hdr_id == id) {
			
			if (instance == 0) {
				return i;
			} else {
				instance --;
			}
		}
	}

	return -1;
}

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

jclass    pcapPacketClass = 0;
jmethodID pcapPacketConstructorMID = 0;

jfieldID pcapStateFID = 0;
jfieldID pcapHeaderFID = 0;


/*
 * Class:     org_jnetpcap_packet_PcapPacket
 * Method:    initIds
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_PcapPacket_initIds
  (JNIEnv *env, jclass clazz) {
	
	pcapPacketClass = (jclass) env->NewGlobalRef(clazz);
	
	if ( (pcapPacketConstructorMID = env->GetMethodID(clazz, 
			"<init>", "(Lorg/jnetpcap/nio/JMemory$Type;)V")) == NULL) {
		
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize method PcapPacket(Type)");
		fprintf(stderr, "Unable to initialize method PcapPacket(Type)");
		return;
	}

	if ( ( pcapStateFID = env->GetFieldID(
			clazz, 
			"state", 
			"Lorg/jnetpcap/packet/JPacket$State;")) == NULL) {
		
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPacket.State:JPacket.State");
		return;
	}
	
	if ( ( pcapHeaderFID = env->GetFieldID(
			clazz, 
			"header", 
			"Lorg/jnetpcap/PcapHeader;")) == NULL) {
		
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPacket.header:PcapHeader");
		return;
	}


}


/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    sizeof
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_sizeof__I
(JNIEnv *env, jclass clazz, jint count) {
	
	return (jint) sizeof(packet_state_t) + sizeof(header_t) * count;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    findHeaderIndex
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_findHeaderIndex
  (JNIEnv *env, jobject obj, jint id, jint instance) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	return (jint) findHeaderById(packet, id, instance);
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    get64BitHeaderMap
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_packet_JPacket_00024State_get64BitHeaderMap
  (JNIEnv *env, jobject obj, jint index) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}

	return (jlong) packet->pkt_header_map[index];
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getAnalysis
 * Signature: ()Lorg/jnetpcap/analysis/JAnalysis;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getAnalysis

  (JNIEnv *env, jobject obj) {
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return NULL;
	}

	return packet->pkt_analysis;
}


/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getHeaderCount
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getHeaderCount
  (JNIEnv *env, jobject obj) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}

	return (jint) packet->pkt_header_count;

}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getInstanceCount
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getInstanceCount
  (JNIEnv *env, jobject obj, jint id) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	int count = 0;
	for (int i = 0; i < packet->pkt_header_count; i ++) {
		if (packet->pkt_headers[i].hdr_id == id) {
			count ++;
		}
	}

	return (jint) count;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getFlags
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getFlags
  (JNIEnv *env, jobject obj) {

	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	return (jint) packet->pkt_flags;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    setFlags
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JPacket_00024State_setFlags
  (JNIEnv *env, jobject obj, jint jflags) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return;
	}
	
	packet->pkt_flags = (uint8_t) jflags;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getWirelen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getWirelen
  (JNIEnv *env, jobject obj) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	return (jint) packet->pkt_wirelen;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    setWirelen
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JPacket_00024State_setWirelen
  (JNIEnv *env, jobject obj, jint jwirelen) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return;
	}
	
	packet->pkt_wirelen = (uint32_t) jwirelen;
}



/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getFrameNumber
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getFrameNumber
  (JNIEnv *env, jobject obj) {
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}

	return (jint) packet->pkt_frame_num;
}


/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getHeaderIdByIndex
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getHeaderIdByIndex
  (JNIEnv *env, jobject obj, jint index) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	if (index < 0 || index >= packet->pkt_header_count) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "header index out of range");
		return -1;
	}

	
//	printf("state=%p, index=%d, value=%d, delta=%d\n", 
//			packet,
//			(int) index,
//			(int) packet->pkt_headers[index].hdr_id,
//			(int) ((char *)&packet->pkt_headers[index].hdr_id - (char *)packet));
//	fflush(stdout);

	return (jint) packet->pkt_headers[index].hdr_id;

}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getHeaderLengthByIndex
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getHeaderLengthByIndex
  (JNIEnv *env, jobject obj, jint index) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	if (index < 0 || index >= packet->pkt_header_count) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "header index out of range");
		return -1;
	}

	return (jint) packet->pkt_headers[index].hdr_length;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getHeaderOffsetByIndex
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getHeaderOffsetByIndex
  (JNIEnv *env, jobject obj, jint index) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	if (index < 0 || index >= packet->pkt_header_count) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "header index out of range");
		return -1;
	}

	return (jint) packet->pkt_headers[index].hdr_offset;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    peerHeaderById
 * Signature: (IILorg/jnetpcap/packet/JHeader$State;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_peerHeaderById
  (JNIEnv *env, jobject obj, jint id, jint instance, jobject dst) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	int index = findHeaderById(packet, id, instance);
	if (index == -1) {
		return -1;
	}
	
	setJMemoryPhysical(env, dst, toLong(&packet->pkt_headers[index]));
	jobject keeper = env->GetObjectField(obj, jmemoryKeeperFID);
	env->SetObjectField(dst, jmemoryKeeperFID, keeper);

	return sizeof(header_t);
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    peerHeaderByIndex
 * Signature: (ILorg/jnetpcap/packet/JHeader$State;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_peerHeaderByIndex
  (JNIEnv *env, jobject obj, jint index, jobject dst) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	if (index >= packet->pkt_header_count) {
		return -1;
	}
	
	setJMemoryPhysical(env, dst, toLong(&packet->pkt_headers[index]));

	return sizeof(header_t);
}

/*
 * Class:     org_jnetpcap_packet_JHeader
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JHeader_sizeof
  (JNIEnv *env, jclass clazz) {
	
	return (jint) sizeof(header_t);
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    toDebugStringJPacketState
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_packet_JPacket_00024State_toDebugStringJPacketState
  (JNIEnv *env, jobject obj) {
	
	char buf[15 * 1024];
	buf[0] = '\0';
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return NULL;
	}
	
	int fr = packet->pkt_frame_num;
	
	sprintf(buf, 
			"JPacket.State#%03d: sizeof(packet_state_t)=%d\n"
			"JPacket.State#%03d: sizeof(header_t)=%d and *%d=%d\n"
			"JPacket.State#%03d: pkt_header_map[0]=0x%016X\n"
			"JPacket.State#%03d: pkt_header_map[1]=0x%016X\n"
			"JPacket.State#%03d: pkt_header_map[2]=0x%016X\n"
			"JPacket.State#%03d: pkt_header_map[3]=0x%016X\n"
			"JPacket.State#%03d:         pkt_flags=0x%08X\n"
			"JPacket.State#%03d:  pkt_header_count=%d\n"
			"JPacket.State#%03d:       pkt_wirelen=%d bytes\n"
			"JPacket.State#%03d:        pkt_caplen=%d bytes\n",
			fr, (int) sizeof(packet_state_t),
			fr, (int) sizeof(header_t),
			(int) packet->pkt_header_count,
			(int) sizeof(header_t) * packet->pkt_header_count,
			fr, (int) packet->pkt_header_map[0],
			fr, (int) packet->pkt_header_map[1],
			fr, (int) packet->pkt_header_map[2],
			fr, (int) packet->pkt_header_map[3],
			fr, (int) packet->pkt_flags,
			fr, (int) packet->pkt_header_count,
			fr, (int) packet->pkt_wirelen,
			fr, (int) packet->pkt_caplen);
	
	char *p = buf;
	
	if (packet->pkt_header_count> 32) {
		sprintf(buf + strlen(buf), 
				"JPacket.State#%03d: TOO MANY HEADERS (more than 32)",
				fr);
		
		return env->NewStringUTF(buf);
	}

	p = buf + strlen(buf);

	sprintf(p,
			"JPacket.State#%03d   : "
			"[%17s(%2s/%4s) | %4s |"
			"%7s |"
			"%7s |"
			"%4s | "
			"%7s | "
			"%7s ]\n",
			fr,
			"Protocol",
			"ID",
			"Flag",
			"Start",
			"Prefix",
			"Header",
			"Gap",
			"Payload",
			"Postfix"
			);

	
	for (int i = 0; i < packet->pkt_header_count; i ++) {
		p = buf + strlen(buf);
		
		sprintf(p, 
				"JPacket.State#%03d[%d]: "
				"[%17s(%2d/%04X) | %5d | "
				"%6d | "
				"%6d | "
				"%3d | "
				"%7d | "
				"%7d ]\n",
				fr,	i,
				id2str(packet->pkt_headers[i].hdr_id),
				packet->pkt_headers[i].hdr_id,
				packet->pkt_headers[i].hdr_flags,
				packet->pkt_headers[i].hdr_offset,
				packet->pkt_headers[i].hdr_prefix,
				packet->pkt_headers[i].hdr_length,
				packet->pkt_headers[i].hdr_gap,
				packet->pkt_headers[i].hdr_payload,
				packet->pkt_headers[i].hdr_postfix
				);
		
	}
	
	return env->NewStringUTF(buf);
}

