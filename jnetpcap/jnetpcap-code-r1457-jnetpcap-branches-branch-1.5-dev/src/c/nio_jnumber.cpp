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
#include "org_jnetpcap_nio_JNumber.h"
#include "jnetpcap_utils.h"
#include "export.h"


/*****************************************************************************
 *  These are static and constant unless class file reloads
 */

typedef void *funct_ptr();

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    sizeof
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JNumber_sizeof
  (JNIEnv *env, jclass clazz, jint o) {
	
	jint l;
	
	switch (o) {
	case org_jnetpcap_nio_JNumber_BYTE_ORDINAL:
	case org_jnetpcap_nio_JNumber_CHAR_ORDINAL:
		return sizeof(char);
		
	case org_jnetpcap_nio_JNumber_INT_ORDINAL:
		return sizeof(int);
		
	case org_jnetpcap_nio_JNumber_SHORT_ORDINAL:
		return sizeof(short int);
		
	case org_jnetpcap_nio_JNumber_LONG_ORDINAL:
		return sizeof(long int);
		
	case org_jnetpcap_nio_JNumber_LONG_LONG_ORDINAL:
		return sizeof(long long int);

		
	case org_jnetpcap_nio_JNumber_FLOAT_ORDINAL:
		return sizeof(float);
		
	case org_jnetpcap_nio_JNumber_DOUBLE_ORDINAL:
		return sizeof(double);
		
	case org_jnetpcap_nio_JNumber_MAX_SIZE_ORDINAL:
		return sizeof(void *);
		
	default:
		return -1;
	}
}


/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    intValue
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JNumber_intValue__
  (JNIEnv *env, jobject obj) {
	
	jint *p = (jint *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return 0;
	}
	
	return *p;	
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    intValue
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JNumber_intValue__I
  (JNIEnv *env, jobject obj, jint jvalue) {
	
	jint *p = (jint *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return;
	}
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    byteValue
 * Signature: ()B
 */
JNIEXPORT jbyte JNICALL Java_org_jnetpcap_nio_JNumber_byteValue__
  (JNIEnv *env, jobject obj) {
	
	jbyte *p = (jbyte *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return 0;
	}
	return *p;	
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    byteValue
 * Signature: (B)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JNumber_byteValue__B
  (JNIEnv *env, jobject obj, jbyte jvalue) {
	jbyte *p = (jbyte *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return;
	}
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    shortValue
 * Signature: ()S
 */
JNIEXPORT jshort JNICALL Java_org_jnetpcap_nio_JNumber_shortValue__
  (JNIEnv *env, jobject obj) {
	
	jshort *p = (jshort *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return 0;
	}
	return *p;	
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    shortValue
 * Signature: (S)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JNumber_shortValue__S
  (JNIEnv *env, jobject obj, jshort jvalue) {
	
	jshort *p = (jshort *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return;
	}
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    longValue
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JNumber_longValue__
  (JNIEnv *env, jobject obj) {
	
	jlong *p = (jlong *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return 0;
	}
	return *p;	
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    longValue
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JNumber_longValue__J
  (JNIEnv *env, jobject obj, jlong jvalue) {
	
	jlong *p = (jlong *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return;
	}
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    floatValue
 * Signature: ()F
 */
JNIEXPORT jfloat JNICALL Java_org_jnetpcap_nio_JNumber_floatValue__
  (JNIEnv *env, jobject obj) {
	
	jfloat *p = (jfloat *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return 0;
	}
	return *p;	
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    floatValue
 * Signature: (F)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JNumber_floatValue__F
  (JNIEnv *env, jobject obj, jfloat jvalue) {
	
	jfloat *p = (jfloat *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return;
	}
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    doubleValue
 * Signature: ()D
 */
JNIEXPORT jdouble JNICALL Java_org_jnetpcap_nio_JNumber_doubleValue__
  (JNIEnv *env, jobject obj) {
	
	jdouble *p = (jdouble *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return 0;
	}
	return *p;	
}

/*
 * Class:     org_jnetpcap_nio_JNumber
 * Method:    doubleValue
 * Signature: (D)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JNumber_doubleValue__D
  (JNIEnv *env, jobject obj, jdouble jvalue) {
	
	jdouble *p = (jdouble *)getJMemoryPhysical(env, obj);
	if (p == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "native NULL pointer");
		return;
	}
	*p = jvalue;
}

