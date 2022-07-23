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

#include "jnetpcap_bpf.h"
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"
#include "export.h"



bpf_program *getBpfProgram(JNIEnv *env, jobject obj) {
	
	jlong pt = env->GetLongField(obj, bpfProgramPhysicalFID);

	if (pt == 0) {
		throwException(env, ILLEGAL_STATE_EXCEPTION,
				"BpfProgram is NULL, not possible (bpf_program).");

		return NULL;
	}

	bpf_program *p = (bpf_program *) toPtr(pt);

	return p;
}

void setBpfProgramPhysical(JNIEnv *env, jobject obj, jlong value) {
	env->SetLongField(obj, bpfProgramPhysicalFID, value);
}

/*
 * Disabled. Classes is not fully peered and copies no longer required.
 * We leave the method in here just for reference purposes.
 * 
bpf_program *bpfProgramInitFrom(JNIEnv *env, jobject obj, bpf_program *src) {
	bpf_program *dst = (bpf_program *)malloc(sizeof(bpf_program));
	dst->bf_insns = (bpf_insn *)malloc(src->bf_len * 8); // Each inst is 8 bytes

	memcpy(dst, src, sizeof(bpf_program));
	memcpy(dst->bf_insns, src->bf_insns, src->bf_len * 8);

	setBpfProgramPhysical(env, obj, toLong(dst));

	return dst;
}
*/

/*****************************************************************************
 *  These are static and constant unless class file reloads
 */

jclass bpfProgramClass = 0;

jfieldID bpfProgramPhysicalFID = 0;

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapBpfProgram_initIDs
(JNIEnv *env, jclass clazz) {

	jclass c;
	// PcapBpfProgram class
	if ( (bpfProgramClass = c = findClass(env, "org/jnetpcap/PcapBpfProgram")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapBpfProgram");
		return;
	}

	if ( ( bpfProgramPhysicalFID = env->GetFieldID(c, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapBpfProgram.physical:long");
		return;
	}
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initPeer
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapBpfProgram_initPeer
  (JNIEnv *env, jobject obj) {
	
	bpf_program *b = (bpf_program *)malloc(sizeof(bpf_program));
	if (b == NULL) {
		throwException(env, OUT_OF_MEMORY_ERROR, "");
		return;
	}
	
	b->bf_insns = NULL;
	b->bf_len = 0;
	
	setBpfProgramPhysical(env, obj, toLong(b));
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    cleanup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapBpfProgram_cleanup
(JNIEnv *env , jobject obj) {

	bpf_program *b = getBpfProgram(env, obj);
	if (b == NULL) {
		return; // Exception already thrown
	}

	/*
	 * Frees the data pointed by the bf_insns
	 */
	if (b->bf_insns != NULL) {
		pcap_freecode(b);
	}
	
	/*
	 * Release the main structure
	 */
	free(b);
	setBpfProgramPhysical(env, obj, (jlong) 0);
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initFromBuffer
 * Signature: (Ljava/nio/ByteBuffer;II)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapBpfProgram_initFromBuffer
(JNIEnv *env , jobject jbpf, jobject jbuf, jint jstart, jint jlen) {
	
	bpf_insn* ptr = (bpf_insn*) env->GetDirectBufferAddress(jbuf);
	jlong len = env->GetDirectBufferCapacity(jbuf); 
	
	bpf_program *b = getBpfProgram(env, jbpf);
	if (b == NULL) {
		return; // Exception already thrown
	}

	b->bf_insns = ptr;
	b->bf_len = len / sizeof(bpf_insn);
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    getInstructionCount
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapBpfProgram_getInstructionCount
(JNIEnv *env, jobject jbpf) {

	bpf_program *b = getBpfProgram(env, jbpf);
	if (b == NULL) {
		return -1; // Exception already thrown
	}

	return (jint)b->bf_len;
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    getInstruction
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_PcapBpfProgram_getInstruction
(JNIEnv *env, jobject jbpf, jint index) {

	bpf_program *b = getBpfProgram(env, jbpf);
	if (b == NULL) {
		return -1; // Exception already thrown
	}

	// Check bounds
	if (index < 0 || index >= b->bf_len) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "index must be 0 < index <= len");
		return -1;
	}

	jlong *i = (jlong *)b->bf_insns;
	
	return i[index];
}
