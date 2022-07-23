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
#include <dlfcn.h>
#endif /*WIN32*/

#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"
#include "org_jnetpcap_nio_JMemory.h"
#include "export.h"

int abc;

#ifdef AIX
#include "sys/ldr.h"

struct Dl_info {
  const char* dli_fname;
};
int dladdr(void* s, Dl_info* i) {
   static const size_t bufSize = 4096;
   char buf[bufSize];
   char* pldi = buf;
   int r = loadquery(L_GETINFO,  pldi,  bufSize);
   if (r == -1) {
      i->dli_fname = 0;
      return 0;
   }
   // First is main(), skip.
   ld_info* ldi = (ld_info*)pldi;
   while (ldi->ldinfo_next) {
     pldi += ldi->ldinfo_next;
     ldi = (ld_info*)pldi;
     char* textBegin = (char*)ldi->ldinfo_textorg;
     if (textBegin < s) {
        char* textEnd = textBegin + ldi->ldinfo_textsize;
        if (textEnd > s) {
           i->dli_fname = ldi->ldinfo_filename;
           return 1;
        }
     }
   }
   i->dli_fname = 0;
   return 0;
}
#endif

/* Inaccessible static: LIBRARY */
/*
 * Class:     com_slytechs_library_NativeLibrary
 * Method:    dlopen
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_slytechs_library_NativeLibrary_dlopen
(JNIEnv *env, jclass clazz, jstring lib_name) {

	const char *name = env->GetStringUTFChars(lib_name, NULL);

#ifdef WIN32
	HMODULE handle = GetModuleHandle(TEXT(name));
#else
	char b[1024];
	sprintf(b, "lib%s.so", name);
	void *handle = dlopen((const char*)b, RTLD_LAZY | RTLD_LOCAL);
#ifdef DEBUG
	printf("dlopen(name=%s)=%p error=%s\n", b, handle, dlerror());fflush(stdout);
#endif
#endif

	env->ReleaseStringUTFChars(lib_name, name);
	return toLong(handle);
}

/*
 * Class:     com_slytechs_library_NativeLibrary
 * Method:    dlsymbol
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_slytechs_library_NativeLibrary_dlsymbol
(JNIEnv *env, jclass clazz, jlong handle, jstring symbol_name) {

	const char *name = env->GetStringUTFChars(symbol_name, NULL);

#ifdef WIN32
	FARPROC symbol = GetProcAddress((HMODULE) toPtr(handle), TEXT(name));
#else

	void *symbol = dlsym(toPtr(handle), name);
	dlerror(); // Clear error
	void *lib = toPtr(handle);
	Dl_info info;
	memset(&info, 0, sizeof(Dl_info));
	if (dladdr(symbol, &info) == 0) {

#ifdef DEBUG
		printf("dlsymbol(%p, %s) - FAILURE\n", lib, name);fflush(stdout);
#endif
	} else {
#ifdef DEBUG
		printf("dlsymbol(%p, %s) - Dl_info:\n", lib, name);fflush(stdout);
		printf("dli_fname=%s\n", info.dli_fname);
		printf("dli_fbase=%p\n", info.dli_fbase);
		printf("dli_sname=%s\n", info.dli_sname);
		printf("dli_saddr=%p\n", info.dli_saddr);
		printf("dlsym.symbol=%p\n", symbol);
		fflush(stdout);
#endif
/*
		if (info.dli_fbase != lib) {
			symbol = 0;
		} else {
			symbol = info.dli_saddr;
		}
*/	}
	
	dlerror(); // CLear errors

#endif

	env->ReleaseStringUTFChars(symbol_name, name);
	return toLong((void *) symbol);
}

/*
 * Class:     com_slytechs_library_NativeLibraryReference
 * Method:    dlclose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_slytechs_library_NativeLibraryReference_dlclose
  (JNIEnv *env, jclass clazz, jlong address) {

#ifdef WIN32

	HMODULE handle = (HMODULE)toPtr(address);

//	printf("NativeLibraryReference.dlclose=%p\n", handle);fflush(stdout);
//	FreeLibrary(handle);

#else

	dlclose(toPtr(address));

#endif
}

/*
 * Class:     com_slytechs_library_JNISymbol
 * Method:    registerSymbol
 * Signature: (Ljava/lang/Class;JLjava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_slytechs_library_JNISymbol_registerSymbol
  (JNIEnv *env, jclass clazz, jclass dstClass, jlong address, jstring javaName, jstring jniSignature) {
	if (address == 0) {
		return;
	} else {
		return;
	}

	const char *name = env->GetStringUTFChars(javaName, NULL);
	const char *sig = env->GetStringUTFChars(jniSignature, NULL);

	JNINativeMethod method = {(char *) name, (char *) sig, toPtr(address)};

//	jint status = env->RegisterNatives(dstClass, &method, 1);

	env->ReleaseStringUTFChars(javaName, name);
	env->ReleaseStringUTFChars(jniSignature, sig);

//	return (status == 0) ? JNI_TRUE : JNI_FALSE;

}

