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

//#define ENABLE_ASSERT
#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"
#include "org_jnetpcap_nio_JMemory.h"
#include "org_jnetpcap_nio_JBuffer.h"
#include "export.h"

//#define DEBUG

/****************************************************************
 * **************************************************************
 *
 * NON Java declared native functions. Private scan function
 *
 * **************************************************************
 ****************************************************************/


/****************************************************************
 * **************************************************************
 *
 * Java declared native functions for jMemory class
 *
 * **************************************************************
 ****************************************************************/

jclass jmemoryClass = 0;
jclass jmemoryPoolClass = 0;
jclass jmemoryRefClass = 0;

jmethodID jmemoryToDebugStringMID = 0;
jmethodID jmemoryMaxDirectMemoryBreachMID = 0;
jmethodID jmemorySoftDirectMemoryBreachMID = 0;
jmethodID jmemoryCleanupMID = 0;
jmethodID jmemoryPeer0MID = 0;
jmethodID jmemoryAllocateMID = 0;
jmethodID jmemorySetSize0MID = 0;


jfieldID jmemoryPhysicalFID = 0;
jfieldID jmemoryRefAddressFID = 0;
jfieldID jmemorySizeFID = 0;
jfieldID jmemoryOwnerFID = 0;
jfieldID jmemoryKeeperFID = 0;
jfieldID jmemoryPOINTERFID = 0;
jfieldID jmemoryRefFID = 0;

jobject jmemoryPOINTER_CONST;

jmethodID jmemoryPoolAllocateExclusiveMID = 0;
jmethodID jmemoryPoolDefaultMemoryPoolMID = 0;
jmethodID jmemoryCreateReferenceMID = 0;

jobject defaultMemoryPool = NULL;


/*
 * Global memory usage statistics for jmemory class
 */
memory_usage_t memory_usage;

static void register_natives(JNIEnv *env) {
	if (jmemoryClass == NULL) {
		Java_org_jnetpcap_nio_JMemory_initIDs(env, NULL);
	}
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_initIDs
(JNIEnv *env, jclass clazz) {

	memset(&memory_usage, 0, sizeof(memory_usage_t));

	jclass c;

	if ( (jmemoryClass = c = findClass(env, "org/jnetpcap/nio/JMemory")) == NULL) return;

	if ( ( jmemoryPhysicalFID = env->GetFieldID(c, "physical", "J")) == NULL) return;

	if ( ( jmemorySizeFID = env->GetFieldID(c, "size", "I")) == NULL) return;

	if ( ( jmemoryOwnerFID = env->GetFieldID(c, "owner", "Z")) == NULL) return;

	if ( ( jmemoryKeeperFID = env->GetFieldID(c, "keeper", "Ljava/lang/Object;")) == NULL) return;

	if ( ( jmemoryRefFID = env->GetFieldID(c, "ref", "Lorg/jnetpcap/nio/JMemoryReference;")) == NULL) return;

	if ( ( jmemoryCleanupMID = env->GetMethodID(c, "cleanup", "()V")) == NULL) return;

	if ( ( jmemoryAllocateMID = env->GetMethodID(c, "allocate", "(I)J")) == NULL) return;

	if ( ( jmemoryPeer0MID = env->GetMethodID(c, "peer0", "(JILjava/lang/Object;)I")) == NULL) return;

	if ( ( jmemoryCreateReferenceMID = env->GetMethodID(c, "createReference", "(JJ)Lorg/jnetpcap/nio/JMemoryReference;")) == NULL) return;

	if ( ( jmemorySetSize0MID = env->GetMethodID(c, "setSize0", "(I)V")) == NULL) return;

	if ( ( jmemoryMaxDirectMemoryBreachMID = env->GetStaticMethodID(c, "maxDirectMemoryBreached", "()V")) == NULL) return;
	if ( ( jmemorySoftDirectMemoryBreachMID = env->GetStaticMethodID(c, "softDirectMemoryBreached", "()V")) == NULL) return;

	if ( ( jmemoryToDebugStringMID = env->GetMethodID(c, "toDebugString", "()Ljava/lang/String;")) == NULL) return;

	jclass typeClass;
	if ( (typeClass = findClass(env, "org/jnetpcap/nio/JMemory$Type")) == NULL) return;

	if ( ( jmemoryPOINTERFID = env->GetStaticFieldID(
							typeClass, "POINTER",
							"Lorg/jnetpcap/nio/JMemory$Type;")) == NULL) return;

	jmemoryPOINTER_CONST = env->NewGlobalRef(
			env->GetStaticObjectField(typeClass, jmemoryPOINTERFID));

	if ( (jmemoryPoolClass = c = findClass(env, "org/jnetpcap/nio/JMemoryPool")) == NULL) return;

	if ( ( jmemoryPoolAllocateExclusiveMID = env->GetMethodID(c, "allocateExclusive", "(I)Lorg/jnetpcap/nio/JMemory;")) == NULL) return;

	if ( ( jmemoryPoolDefaultMemoryPoolMID = env->GetStaticMethodID(c, "defaultMemoryPool", "()Lorg/jnetpcap/nio/JMemoryPool;")) == NULL) return;

	if ( (jmemoryRefClass = c = findClass(env, "org/jnetpcap/nio/JMemoryReference")) == NULL) return;
	if ( ( jmemoryRefAddressFID = env->GetFieldID(c, "address", "J")) == NULL) return;

#ifdef DEBUG
	printf("initIds() - SUCCESS");
#endif

	/*
	 * Now initialize some jmemory state that is needed for global memory allocation
	 */
	init_jmemory(env);

	Java_org_jnetpcap_nio_JBuffer_initIds(env, NULL);
}

void init_jmemory(JNIEnv *env) {

	defaultMemoryPool = env->CallStaticObjectMethod(jmemoryPoolClass, jmemoryPoolDefaultMemoryPoolMID);

	if (defaultMemoryPool == NULL) {
		fprintf(stderr, "unable to get default memory pool\n");
		fflush(stderr);
	}
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    allocate0
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_allocate0
  (JNIEnv *env, jclass clazz, jint size) {

#ifdef DEBUG
	printf("\n%p JMemory_allocate0() ENTER\n", env); fflush(stdout);
#endif
	if (memory_usage.available_direct < size) {
		/*
		 * Try to free up memory - blocking
		 */

		env->CallStaticVoidMethod(jmemoryClass, jmemoryMaxDirectMemoryBreachMID);

		if (memory_usage.available_direct < size) {
			throwException(env, OUT_OF_MEMORY_ERROR, "");
			return 0L;
		}
	} else if (memory_usage.reserved_direct > memory_usage.soft_direct) {
		/*
		 * Try to free up memory - non-blocking
		 * Also can only be invoked consecutively after a certain amount of time
		 */
		env->CallStaticVoidMethod(jmemoryClass, jmemorySoftDirectMemoryBreachMID);
	}

	memory_usage.available_direct -= size;
	memory_usage.reserved_direct += size;

#ifdef DEBUG
	printf("%p JMemory_allocate0() malloc size=%d\n", env, size); fflush(stdout);
#endif
	void *mem = malloc(size);
	if (mem == NULL) {
//		printf("%p EXCEPTION mem==NULL\n", env); fflush(stdout);
		throwException(env, OUT_OF_MEMORY_ERROR, "");
		return 0L;
	}


#ifdef DEBUG
	printf("%p jmemoryAllocate() usage\n", env); fflush(stdout);
#endif
	memory_usage.total_allocated += size;
	memory_usage.total_allocate_calls ++;

	if (size <= 255) {
		memory_usage.seg_0_255_bytes ++;
	} else {
		memory_usage.seg_256_or_above_bytes ++;
	}
#ifdef DEBUG
	printf("%p jmemoryAllocate() EXIT\n", env); fflush(stdout);
#endif
	return (jlong) toLong(mem);
}


/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    availableDirectMemory
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_availableDirectMemory
  (JNIEnv *env, jclass clazz) {
	return (jlong) memory_usage.available_direct;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    reservedDirectMemory
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_reservedDirectMemory
  (JNIEnv *env, jclass clazz) {
	return (jlong) memory_usage.reserved_direct;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    setMaxDirectMemorySize
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_setMaxDirectMemorySize
  (JNIEnv *env, jclass clazz, jlong size) {

	int64_t delta = ((int64_t)size - (int64_t)memory_usage.max_direct);
	memory_usage.max_direct = size;
	memory_usage.available_direct += delta;

}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    setSoftDirectMemorySize
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_setSoftDirectMemorySize
  (JNIEnv *env, jclass clazz, jlong size) {

	memory_usage.soft_direct = size;
}


/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocateCalls
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocateCalls(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_allocate_calls;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocated
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocated(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_allocated;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocatedSegments0To255Bytes
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocatedSegments0To255Bytes(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.seg_0_255_bytes;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocatedSegments256OrAbove
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocatedSegments256OrAbove(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.seg_256_or_above_bytes;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalDeAllocateCalls
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalDeAllocateCalls(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_deallocate_calls;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalDeAllocated
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalDeAllocated(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_deallocated;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    allocate
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_allocate
(JNIEnv *env, jobject obj, jint jsize) {

	jmemoryAllocate(env, (size_t) jsize, obj);
}

/*
 * Class:     org_jnetpcap_nio_JMemoryReference
 * Method:    disposeNative0
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemoryReference_disposeNative0
(JNIEnv *env, jobject obj, jlong address, jlong size) {

	void * ptr = toPtr(address);

	if (ptr != NULL) {
		memory_usage.total_deallocated += size;
		memory_usage.total_deallocate_calls ++;
		memory_usage.available_direct += size;
		memory_usage.reserved_direct -= size;

		free(ptr);
	}
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    cleanup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_cleanup
(JNIEnv *env, jobject obj) {

	jmemoryCleanup(env, obj);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    nativePeer
 * Signature: (Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_peer(JNIEnv *env,
		jobject obj, jobject jbytebuffer) {

	if (jbytebuffer == NULL || byteBufferIsDirectMID == NULL) {
		char buf[1024];
		sprintf(buf, "jbytebuffer=%p byteBufferIsDirectMID=%p\n", jbytebuffer, byteBufferIsDirectMID);
		throwException(env, NULL_PTR_EXCEPTION, buf);
		return -1;
	}

	if (env->CallBooleanMethod(jbytebuffer, byteBufferIsDirectMID) == JNI_FALSE) {
		throwException(env, ILLEGAL_ARGUMENT_EXCEPTION,
				"Can only peer with direct ByteBuffer objects");
		return -1;
	}

	void *mem = getJMemoryPhysical(env, obj);
	if (mem != NULL) {
		Java_org_jnetpcap_nio_JMemory_cleanup(env, obj);
	}

	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);

	char *b = (char *) env->GetDirectBufferAddress(jbytebuffer);
	setJMemoryPhysical(env, obj, toLong(b + position));

	env->SetIntField(obj, jmemorySizeFID, (jint)(limit - position));
	env->SetObjectField(obj, jmemoryKeeperFID, jbytebuffer);

	return (limit - position);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferFrom
 * Signature: ([BIII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFrom___3BIII(
		JNIEnv *env, jobject obj, jbyteArray sa, jint soffset, jint len,
		jint doffset) {

	jbyte *src = (jbyte *) getJMemoryPhysical(env, obj);
	if (src == NULL || sa == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	env->GetByteArrayRegion(sa, soffset, len, (src + doffset));

	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferFromDirect
 * Signature: (Ljava/nio/ByteBuffer;I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFromDirect(
		JNIEnv *env, jobject obj, jobject jbytebuffer, jint offset) {

	char *dst = (char *) getJMemoryPhysical(env, obj);
	if (dst == NULL || jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);
	jsize len = limit - position;

	size_t size = env->GetIntField(obj, jmemorySizeFID);

#ifdef DEBUG
	printf("JMemory.transferFrom(ByteBuffer): position=%d limit=%d len=%d\n",
			position, limit, len);
	fflush(stdout);
#endif

	if (size < len) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	char *b = (char *) env->GetDirectBufferAddress(jbytebuffer);

	memcpy((void *) (dst + offset), b + position, len);

	env->CallObjectMethod(jbytebuffer, bufferSetPositionMID, position + len);

	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo0
 * Signature: (J[BIII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo0
(JNIEnv *env, jclass clazz, jlong address, jbyteArray da, jint soffset, jint len,
		jint doffset) {

	jbyte *src = (jbyte *)toPtr(address);

	env->SetByteArrayRegion(da, doffset, len, (src + soffset));

	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo
 * Signature: (Lorg/jnetpcap/nio/JMemory;III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo
		(JNIEnv *env, jobject obj, jobject jdst, jint jsrcOffset, jint jlen,
		jint jdstOffset) {

	char *src = (char *) getJMemoryPhysical(env, obj);
	if (src == NULL || jdst == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	char *dst = (char *) getJMemoryPhysical(env, jdst);
	if (dst == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	size_t srcLen = env->GetIntField(obj, jmemorySizeFID);
	size_t dstLen = env->GetIntField(jdst, jmemorySizeFID);

	if (jsrcOffset < 0 || jdstOffset < 0 || jsrcOffset + jlen > srcLen
			|| jdstOffset + jlen > dstLen) {

		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "");
		return -1;
	}

	jlen = (dstLen < jlen) ? dstLen : jlen;

//	printf("\nJMemory_2III() dst=%p off=%d src=%p off=%d len=%d",
//			dst, jdstOffset,
//			src, jsrcOffset,
//			jlen);
//	fflush(stdout);

	memcpy((void *) (dst + jdstOffset), (void *) (src + jsrcOffset), jlen);

	return jlen;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferToDirect
 * Signature: (Ljava/nio/ByteBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferToDirect
		(JNIEnv *env, jobject obj, jobject jbytebuffer, jint jsrcOffset,
		jint len) {

#ifdef DEBUG
	printf("JMemory.transferTo(ByteBuffer): enter\n");
	fflush(stdout);
#endif

	register_natives(env);

	ASSERT(obj != NULL);
	char *src = (char *) getJMemoryPhysical(env, obj);
	if (src == NULL || jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	ASSERT(obj != NULL);
	ASSERT(jbytebuffer != NULL);
	ASSERT(bufferGetLimitMID != NULL);
	ASSERT(bufferGetPositionMID != NULL);
	ASSERT(jmemorySizeFID != NULL);

	//	jint capacity = env->CallIntMethod(jbytebuffer, bufferGetCapacityMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);
	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jsize dstLen = limit - position;
	size_t srcLen = env->GetIntField(obj, jmemorySizeFID);

	if (jsrcOffset < 0 || (jsrcOffset + len) > srcLen) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);

		return -1;
	}

	if (dstLen < len) {
		throwVoidException(env, BUFFER_OVERFLOW_EXCEPTION);
		return -1;
	}

	char *b = (char *) env->GetDirectBufferAddress(jbytebuffer);
	ASSERT(b != NULL);

#ifdef DEBUG
	printf("JMemory.transferTo(ByteBuffer): position=%d limit=%d len=%d\n",
			position, limit, len);
	fflush(stdout);
#endif
	memcpy(b + position, (void *) (src + jsrcOffset), len);

	env->CallObjectMethod(jbytebuffer, bufferSetPositionMID, position + len);

	return len;
}

void *getJMemoryPhysical(JNIEnv *env, jobject obj) {

	jlong pt = env->GetLongField(obj, jmemoryPhysicalFID);
	return toPtr(pt);
}


void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value) {
	/*
	 * Make sure we clean up any previous allocations before we set new ptr
	 * and loose track of the old memory. In essence, this call in this function
	 * makes all JMemory.peer functions call JMemory.cleanup ;)
	 */
	jmemoryCleanup(env, obj);

	env->SetLongField(obj, jmemoryPhysicalFID, value);

//	printf("setJMemoryPhysical() obj=%p mem=%p\n", obj, toPtr(value));fflush(stdout);
//	char buf[1024];
//	printf("%s\n", jmemoryToDebugString(env, obj, buf));
}

/**
 * Function calls on the java JMemory.createReference method and passes it the
 * address of this jmemory native pointer (usually memory pointer). The java
 * method may be overriden or returns the default new instance of
 * JMemoryReference object. The function is marked static to prevent anyone else
 * outside of nio_jmemory method using it. It would be very dangerous to try
 * and create new JMemoryReference objects outside. This should only be done
 * from jmemoryAllocate and from transferOwnership methods.
 */
static jobject jmemoryCreateReference(JNIEnv *env, jobject obj, void *address, size_t size) {
	return env->CallObjectMethod(
			obj,
			jmemoryCreateReferenceMID,
			toLong(address),
			(jlong)size);
}

char *jmemoryToDebugString(JNIEnv *env, jobject obj, char *buf) {
	jstring jstr = (jstring) env->CallObjectMethod(obj, jmemoryToDebugStringMID);
	if (jstr == NULL) {
		return (char *)"ERROR in jmemoryToDebugString";
	}

	int len = env->GetStringUTFLength(jstr);
	const char *str = env->GetStringUTFChars(jstr, NULL);
	buf[len] = '\0';
	strncpy(buf, str, len);
	env->ReleaseStringUTFChars(jstr, str);

	return buf;
}

void jmemoryCleanup(JNIEnv *env, jobject obj) {
	env->CallVoidMethod(obj, jmemoryCleanupMID);
}

/**
 * Change the size of the peered object. The physicalSize remains unchanged.
 */
void jmemoryResize(JNIEnv *env, jobject obj, size_t size) {
	env->CallVoidMethod(obj, jmemorySetSize0MID, (jint) size);
}


/**
 * Provides a flexible peer method that can be called from JNI code
 */
jint jmemoryPeer(JNIEnv *env, jobject obj, const void *ptr, size_t length,
		jobject owner) {

	return env->CallIntMethod(obj, jmemoryPeer0MID,
			(jlong) toLong((void *) ptr), (jint) length, owner);
}

/**
 * Allocates a memory block that is JMemory managed. The memory is allocated
 * under the control of the global memory pool (a java object).
 *
 * @param env
 * 	   java environment
 * @param size
 *     amount of memory to allocate in bytes
 * @param obj_ref
 *     a pointer to where store the JMemory object reference that owns the
 *     allocated memory block
 */
char *jmemoryPoolAllocate(JNIEnv *env, size_t size, jobject *obj_ref) {

	*obj_ref = env->CallObjectMethod(jmemoryPoolClass, jmemoryPoolAllocateExclusiveMID, (jint) size);

	return (char *) getJMemoryPhysical(env, *obj_ref);
}

/**
 * Allocates a single memory block for the java obj as its owner.
 *
 * @param env
 * 	   java environment
 * @param size
 *     amount of memory to allocate in bytes
 * @param obj
 *     obj under which to allocate the memory
 */
char *jmemoryAllocate(JNIEnv *env, size_t size, jobject obj) {
	return (char *)toPtr(env->CallLongMethod(obj, jmemoryAllocateMID, size));
}
