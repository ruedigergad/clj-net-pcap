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
#include <netinet/in.h>
#include <unistd.h>
#endif /*WIN32*/

#ifdef WIN32
#include <winsock2.h>    // Ws2def.h - Vista onward
#include <Ws2tcpip.h>    // Before Vista
// #include <Ws2ipdef.h> // On Vista onward
#include <iphlpapi.h>
#endif /*WIN32*/

#include "jnetpcap_ids.h"

#include "mac_addr.h" // Defines socket and DLPI based MAC address getters

#include "jnetpcap_utils.h"
#include "jnetpcap_bpf.h"
#include "nio_jmemory.h"
#include "export.h"




/*****************************************************************************
 * UTILITY METHODS
 */

const char *toCharArray(JNIEnv *env, jstring jstr, char *buf) {

	const char *s = env->GetStringUTFChars(jstr, NULL);
	strcpy(buf, s);

	env->ReleaseStringUTFChars(jstr, s);

	return buf;
}

jstring toJavaString(JNIEnv *env, const char *buf) {
	jstring s = env->NewString((jchar *)buf, (jsize) strlen(buf));

	return s;
}

jlong toLong(void *ptr) {
#ifndef WIN32
	jlong lp = (intptr_t) ptr;
#else
	jlong lp = (UINT_PTR) ptr;
#endif

	return lp;
}

void *toPtr(jlong lp) {

#ifndef WIN32
	void *ptr = (void *) ((intptr_t) lp);
#else
	void *ptr = (void *) ((UINT_PTR) lp);
#endif


	return ptr;
}

/*****************************************************************************
 *  These are static and constant unless class file reloads
 */


jmethodID findMethod(JNIEnv *env, jobject obj, const char *name, const char *signature) {
	jclass clazz = (jclass)env->GetObjectClass(obj);
	if (clazz == NULL) {
		return 0; // Out of memory exception already thrown
	}

	jmethodID id;
	if ( (id = env->GetMethodID(clazz, name, signature)) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION, name);
		return 0;
	}

	env->DeleteLocalRef(clazz);

	return id;
}


/**
 * Find class or throw exception if not found.
 *
 * @return global reference to class that needs to be freed manually before
 *         library exit
 */
jclass findClass(JNIEnv *env, const char *name) {
	// List class
	jclass local;
	if ( (local = env->FindClass(name)) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION, name);
		return NULL;
	}

	jclass global = (jclass) env->NewGlobalRef(local);

	env->DeleteLocalRef(local);

	if (global == NULL) {
		return NULL; // Out of memory exception already thrown
	}

	return global;
}


pcap_t *getPcap(JNIEnv *env, jobject obj) {
	jlong pt = env->GetLongField(obj, pcapPhysicalFID);

	if (pt == 0) {
		throwException(env, PCAP_CLOSED_EXCEPTION, NULL);

		return NULL;
	}

	pcap_t *p = (pcap_t *) toPtr(pt);

	return p;
}

jlong getPhysical(JNIEnv *env, jobject obj) {
	jlong physical = env->GetLongField(obj, pcapPhysicalFID);

	return physical;
}

void setPhysical(JNIEnv *env, jobject obj, jlong value) {
	env->SetLongField(obj, pcapPhysicalFID, value);
}

void setPktHeader(JNIEnv *env, jobject jpkt_header, pcap_pkthdr *pkt_header) {

	env->SetLongField(jpkt_header, PcapPktHdrSecondsFID,
			(jlong)pkt_header->ts.tv_sec);

	env->SetIntField(jpkt_header, PcapPktHdrUSecondsFID,
			(jint)pkt_header->ts.tv_usec);

	env->SetIntField(jpkt_header, PcapPktHdrCaplenFID, (jint)pkt_header->caplen);

	env->SetIntField(jpkt_header, PcapPktHdrLenFID, (jint)pkt_header->len);
}

/*
 * Function: getPktHeader
 * Description: extracts the contents of PcapPktHdr java object into a
 *              pcap_pkthdr structure.
 * Return: the supplied structured filled in or if null, new allocated one.
 */
pcap_pkthdr *getPktHeader(JNIEnv *env, jobject jpkt_header, pcap_pkthdr *pkt_header) {

	if (pkt_header == NULL) {
		pkt_header = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr));
	}

	pkt_header->ts.tv_sec = (int) env->GetLongField(jpkt_header, PcapPktHdrSecondsFID);

	pkt_header->ts.tv_usec = (int) env->GetIntField(jpkt_header, PcapPktHdrUSecondsFID);

	pkt_header->caplen = (int) env->GetIntField(jpkt_header, PcapPktHdrCaplenFID);

	pkt_header->len = (int) env->GetIntField(jpkt_header, PcapPktHdrLenFID);

	return pkt_header;
}

void setPktBuffer(JNIEnv *env, jobject jpkt_buffer, jobject jbuffer) {
	env->SetObjectField(jpkt_buffer, PcapPktBufferFID, jbuffer);
}

/*
 * Throws specified exception with message to java. Any method calling on
 * this utility class, needs to make sure it returns as this exception does
 * not transfer control to back to java like it is in Java language, but returns
 * immediately.
 */
void throwException(JNIEnv *env, const char *excClassName, const char *message) {
	jclass exception = env->FindClass(excClassName);

	if (exception != NULL) {
		env->ThrowNew(exception, message);
	}
}

/*
 * Throws specified exception with message to java. Any method calling on
 * this utility class, needs to make sure it returns as this exception does
 * not transfer control to back to java like it is in Java language, but returns
 * immediately.
 */
void throwVoidException(JNIEnv *env, const char *excClassName) {
	jclass clazz = env->FindClass(excClassName);

	jmethodID constructorMID;
	if ( (constructorMID = env->GetMethodID(clazz, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize exception class ");
		return;
	}

	if (clazz != NULL) {
		jthrowable exception = (jthrowable)env->NewObject(clazz, constructorMID);
		env->Throw(exception);
	}
}


/**
 * Calls on StringBuilder.setLength(0) and StringBuilder.append(String)
 */
void setString(JNIEnv *env, jobject buffer, const char *str) {

	if (str == NULL) {
		str = "";
	}

	jstring jstr = env->NewStringUTF(str);

	env->CallVoidMethod(buffer, setLengthMID, 0); // Set buffer to 0 length

	env->CallObjectMethod(buffer, appendMID, jstr); // append our string
	return;
}

/**
 * Creates a new instance of Java PcapIf object, intializes all of its fields
 * from pcap_if_t structure and add the resulting element to jlist which is
 * a Java java.util.List object. The method id is cached but has to discovered
 * upon the first entry into findDevsAll since we don't know exactly the type
 * of actual object implementing the List interface. Could be ArrayList,
 * LinkedList or some other custom list. So that is the reason for the dynamic
 * methodID lookup. We pass the ID along to reuse it through out the life of
 * this recursive scan.
 *
 * @param obj Pcap
 * @param jlist java.util.list to which we will add this PcapIf element
 * @param MID_add cached dynamic method ID of the "add" method
 * @param ifp pcap_if_t structure to use in construction of java counter part
 * @return PcapIf
 */
jobject newPcapIf(JNIEnv *env, jobject jlist, jmethodID MID_add, pcap_if_t *ifp) {
	jobject js;

	// Invoke new PcapIf()
	jobject obj = env->NewObject(pcapIfClass, pcapIfConstructorMID);

	/*
	 * Initialize PcapIf.next field. Also add the new PcapIf object that went
	 * into the field to the use supplied jlist.
	 */
	if (ifp->next != NULL) {
		jobject jpcapif = newPcapIf(env, jlist, MID_add, ifp->next);
		if (jpcapif == NULL) {
			return NULL; // Out of memory exception already thrown
		}

		env->SetObjectField(obj, pcapIfNextFID, jpcapif);
		if (env->CallBooleanMethod(jlist, MID_add, jpcapif) == JNI_FALSE) {
			env->DeleteLocalRef(jpcapif);
			return NULL; // Failed to add to the list
		}

		env->DeleteLocalRef(jpcapif);
	} else {
		env->SetObjectField(obj, pcapIfNextFID, NULL);
	}

	/**
	 * Assign PcapIf.name string field.
	 */
	if (ifp->name != NULL) {

		js = env->NewStringUTF(ifp->name);
		if (js == NULL) {
			return NULL; // Out of memory exception already thrown
		}

		env->SetObjectField(obj, pcapIfNameFID, js);

		env->DeleteLocalRef(js);

	} else {
		env->SetObjectField(obj, pcapIfNameFID, NULL);
	}

	/**
	 * Assign PcapIf.description string field.
	 */
	if (ifp->description != NULL) {
		js = env->NewStringUTF(ifp->description);
		if (js == NULL) {
			return NULL; // Out of memory exception already thrown
		}
		env->SetObjectField(obj, pcapIfDescriptionFID, js);

		env->DeleteLocalRef(js);
	} else {
		env->SetObjectField(obj, pcapIfDescriptionFID, NULL);
	}

	/**
	 * Add all addresses found in pcap_if.address linked list of sockaddr to
	 * the already Java allocated list in the PcapIf.addresses field.
	 */
	if (ifp->addresses != NULL) {

		// Lookup field and the List object from PcapIf.addresses field
		jobject jaddrlist = env->GetObjectField(obj, pcapIfAddressesFID);
		if (jaddrlist == NULL) {
			return NULL; // Exception already thrown
		}

		// Lookup List.add method ID within the object, can't be static as this
		// is a interface lookup, not a known object type implementing the
		// interface
		jmethodID MID_addr_add = findMethod(env, jaddrlist, "add",
				"(Ljava/lang/Object;)Z");
		if (MID_addr_add == NULL) {
			env->DeleteLocalRef(jaddrlist);
			return NULL; // Exception already thrown
		}

		// Process the structure and get the next addr
		jobject jaddr = newPcapAddr(env, jaddrlist, MID_addr_add, ifp->addresses);
		if (jaddr == NULL) {
			env->DeleteLocalRef(jaddrlist);
			return NULL; // Out of memory exception already thrown
		}

		// Call on List.add method to add our new PcapAddr object
		if (env->CallBooleanMethod(jaddrlist, MID_addr_add, jaddr) == JNI_FALSE) {
			env->DeleteLocalRef(jaddrlist);
			env->DeleteLocalRef(jaddr);
			return NULL; // Failed to add to the list
		}

		// Release local resources
		env->DeleteLocalRef(jaddr);
		env->DeleteLocalRef(jaddrlist);
	}

	env->SetIntField(obj, pcapIfFlagsFID, (jint) ifp->flags);

	return obj;
}

jobject newPcapAddr(JNIEnv *env, jobject jlist, jmethodID MID_add, pcap_addr *a) {
	jobject obj = env->NewObject(pcapAddrClass, pcapAddrConstructorMID);

	if (a->next != NULL) {
		jobject jaddr = newPcapAddr(env, jlist, MID_add, a->next);
		if (jaddr == NULL) {
			env->DeleteLocalRef(jaddr);
			return NULL;
		}

		// Set the next field for the hell of it, not accessed in java
		env->SetObjectField(obj, pcapAddrNextFID, jaddr);

		// Call List.add method to add our PcapAddr object
		if (env->CallBooleanMethod(jlist, MID_add, jaddr) == JNI_FALSE) {
			env->DeleteLocalRef(jaddr);
			return NULL;
		}

	} else {
		env->SetObjectField(obj, pcapAddrNextFID, NULL);
	}

	jobject jsock;
	if (a->addr != NULL) {
		if ( (jsock = newPcapSockAddr(env, a->addr)) == NULL) {
			return NULL;
		}

		env->SetObjectField(obj, pcapAddrAddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrAddrFID, NULL);
	}

	if (a->netmask != NULL) {
		if ( (jsock = newPcapSockAddr(env, a->netmask)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrNetmaskFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrNetmaskFID, NULL);
	}

	if (a->broadaddr != NULL) {
		if ( (jsock = newPcapSockAddr(env, a->broadaddr)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrBroadaddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrBroadaddrFID, NULL);
	}

	if (a->dstaddr != NULL) {
		if ( (jsock = newPcapSockAddr(env, a->dstaddr)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrDstaddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrDstaddrFID, NULL);
	}

	return obj;
}

jobject newPcapSockAddr(JNIEnv *env, sockaddr *a) {
	jobject obj = env->NewObject(PcapSockAddrClass, PcapSockAddrConstructorMID);

	env->SetShortField(obj, PcapSockAddrFamilyFID, (jshort) a->sa_family);

	if (a->sa_family == AF_INET) {
		jbyteArray jarray = env->NewByteArray(4);
		env->SetByteArrayRegion(jarray, 0, 4, (jbyte *)(a->sa_data + 2));

		env->SetObjectField(obj, PcapSockAddrDataFID, jarray);

		env->DeleteLocalRef(jarray);
	} else if (a->sa_family == AF_INET6) {
		jbyteArray jarray = env->NewByteArray(16);
		env->SetByteArrayRegion(jarray, 0, 16, (jbyte *)&((struct sockaddr_in6 *)a)->sin6_addr);

		env->SetObjectField(obj, PcapSockAddrDataFID, jarray);
		env->DeleteLocalRef(jarray);
	} else {
		jbyteArray jarray = env->NewByteArray(14); // Has to be atleast 14 bytes
		env->SetByteArrayRegion(jarray, 0, 14, (jbyte *)(a->sa_data + 2));

		env->SetObjectField(obj, PcapSockAddrDataFID, jarray);
		env->DeleteLocalRef(jarray);

//		printf("Unknow sockaddr family=%d\n", a->sa_family);
	}

	return obj;
}

void setPcapStat(JNIEnv *env, jobject jstats, pcap_stat *stats) {

	env->SetLongField(jstats, pcapStatRecvFID, (jlong) stats->ps_recv);
	env->SetLongField(jstats, pcapStatDropFID, (jlong) stats->ps_drop);
	env->SetLongField(jstats, pcapStatIfDropFID, (jlong) stats->ps_ifdrop);
}

/****************************************************************
 * **************************************************************
 *
 * MS Ip Helper API calls
 *
 * **************************************************************
 ****************************************************************/
#ifdef WIN32

/*
 * Get interface info, which contains Adapter[] that has the MIB index
 */
PIP_INTERFACE_INFO getIpInterfaceInfo(void) {

	DWORD size = 0;
	PIP_INTERFACE_INFO  info = NULL;

	// Get the require size of the structure
	if (GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER) {
		info = (PIP_INTERFACE_INFO) malloc(size);
	} else {
		return NULL;
	}

	// Now fill in the structure
	GetInterfaceInfo(info, &size);

	return info;
}


/*
 * MS get mib row
 */
PMIB_IFROW getMibIfRow (int index) {

	PMIB_IFROW row = (PMIB_IFROW) malloc(sizeof(MIB_IFROW));

	row->dwIndex = index;

	// Get the require size of the structure
	if (row != NULL && GetIfEntry(row) == NO_ERROR) {
		return row;
	} else {
		return NULL;
	}
}


#endif // WIN32


/****************************************************************
 * **************************************************************
 *
 * Java declared native functions
 *
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_PcapUtils
 * Method:    getHardwareAddress
 * Signature: (Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_PcapUtils_getHardwareAddress
  (JNIEnv *env, jclass clazz, jstring jdevice) {

#ifndef IFNAMSIZ
#define IFNAMSIZ 512
#endif

	jbyteArray jba = NULL;
	char buf[IFNAMSIZ];

	// convert from jstring to char *
	toCharArray(env, jdevice, buf);

#ifdef WIN32

	PIP_INTERFACE_INFO info = getIpInterfaceInfo();

	if (info == NULL) {
		throwException(env, IO_EXCEPTION,
				"unable to retrieve interface info");
		return NULL;
	}

	for (int i = 0; i < info->NumAdapters; i ++) {
		PIP_ADAPTER_INDEX_MAP map = &info->Adapter[i];


		/*
		 * Name is in wide character format. So convert to plain UTF8.
		 */
		int size=WideCharToMultiByte(0, 0, map->Name, -1, NULL, 0, NULL, NULL);
		char utf8[size + 1];
		WideCharToMultiByte(0, 0, map->Name, -1, utf8, size, NULL, NULL);

#ifdef DEBUG
		printf("#%d name=%s buf=%s\n", i, utf8, buf); fflush(stdout);
#endif

		char *p1 = strchr(utf8, '{');
		char *p2 = strchr(buf,  '{');

		if(p1 == NULL || p2 == NULL) {
			p1 = utf8;
			p2 = buf;
		}

		if (strcmp(p1, p2) == 0) {
			PMIB_IFROW row = getMibIfRow(map->Index);
#ifdef DEBUG
			printf("FOUND index=%d len=%d\n", map->Index, row->dwPhysAddrLen); fflush(stdout);
#endif

			jba = env->NewByteArray((jsize) row->dwPhysAddrLen);

			env->SetByteArrayRegion(jba, (jsize) 0, (jsize) row->dwPhysAddrLen,
					(jbyte *)row->bPhysAddr);

			free(row);
		}
	}

	free(info);

#else

	u_char mac[6]; // MAC address is 6 bytes

#if defined(Linux) || defined(HPUX) || defined(AIX) || defined(DARWIN) || \
		defined(FREE_BSD) || defined(NET_BSD) || defined(OPEN_BSD)

	mac_addr_sys(buf, mac);

#else

	mac_addr_dlpi(buf, mac);

#endif

    jba = env->NewByteArray((jsize) 6);
    env->SetByteArrayRegion(jba, 0, 6, (jbyte *)mac);
#endif

	return jba;
}

/*
 * Class:     org_jnetpcap_PcapUtils
 * Method:    injectLoop
 * Signature: (IILorg/jnetpcap/packet/PcapPacketHandler;Ljava/lang/Object;Lorg/jnetpcap/packet/PcapPacket;Lorg/jnetpcap/packet/JPacket$State;Lorg/jnetpcap/PcapHeader;Lorg/jnetpcap/packet/JScanner;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapUtils_injectLoop
(JNIEnv *env, jclass zz,
		jint jcnt,
		jint id,
		jobject jhandler,
		jobject juser,
		jobject jpacket,
		jobject jstate,
		jobject jheader,
		jobject jscanner) {

//	printf("LOOP-JPacketHandler\n"); fflush(stdout);
	if (jhandler == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	/*
	 * Structure to encapsulate user data object, and store our JNI information
	 * so we can dispatch to Java land.
	 */
	cb_jpacket_t data;
	memset(&data, 0, sizeof(data));
	data.env = env;
	data.obj = jhandler;
	data.pcap = NULL;
	data.user = juser;
	data.header = jheader;
	data.packet = jpacket;
	data.state = jstate;
	data.id = id;
	data.scanner = jscanner;
	jclass clazz = env->GetObjectClass(jhandler);
	data.p = NULL;
	data.flags = 0;

	data.mid = env->GetMethodID(clazz, "nextPacket",
			"(Lorg/jnetpcap/packet/PcapPacket;Ljava/lang/Object;)V");
	if (data.mid == NULL) {
		return -1;
	}

	const pcap_pkthdr *pkt_header = (const pcap_pkthdr *)getJMemoryPhysical(env, jheader);
	const u_char *pkt_data = (const u_char *)getJMemoryPhysical(env, jheader);

	for (int i = 0; i < jcnt || jcnt == -1; i ++) {
		cb_pcap_packet_dispatch((u_char *)&data, pkt_header, pkt_data);
		if (data.exception != NULL) {
			env->Throw(data.exception);
			break;
		}

		if (data.flags & DEBUG_INJECT_PACKET_BREAK_LOOP) {
			break;
		}

	}

	return jcnt;
}



/*
 * Legacy ByteBuffer dispatch function - deprecated.
 */
void pcap_callback(u_char *user, const pcap_pkthdr *pkt_header,
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

	env->CallNonvirtualVoidMethod(
			data->obj,
			data->clazz,
			data->mid,
			(jobject) data->user,
			(jlong) pkt_header->ts.tv_sec,
			(jint)pkt_header->ts.tv_usec,
			(jint)pkt_header->caplen,
			(jint)pkt_header->len, buffer);

	env->DeleteLocalRef(buffer);
	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
		pcap_breakloop(data->p);
	}
}

/**
 * ByteBuffer dispatcher that allocates a new java.nio.ByteBuffer and dispatches
 * it to java listener.
 */
void cb_byte_buffer_dispatch(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	cb_byte_buffer_t *data = (cb_byte_buffer_t *)user;

	JNIEnv *env = data->env;

	setJMemoryPhysical(env, data->header, toLong((void*)pkt_header));

	jobject buffer = env->NewDirectByteBuffer((void *)pkt_data,
			pkt_header->caplen);
	if (buffer == NULL) {
		return;
	}

	env->CallVoidMethod(
			data->obj,
			data->mid,
			(jobject) data->header,
			(jobject) buffer,
			(jobject) data->user);

	env->DeleteLocalRef(buffer);

	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
		pcap_breakloop(data->p);
	}
}

/**
 * JBuffer dispatcher that dispatches JBuffers, without allocating the buffer
 */
void cb_jbuffer_dispatch(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	cb_jbuffer_t *data = (cb_jbuffer_t *)user;

	JNIEnv *env = data->env;

	jmemoryPeer(env, data->header, pkt_header, sizeof(pcap_pkthdr), data->pcap);
	jmemoryPeer(env, data->buffer, pkt_data, pkt_header->caplen, data->pcap);


	env->CallVoidMethod(
			data->obj,
			data->mid,
			data->header,
			data->buffer,
			data->user);

	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
		pcap_breakloop(data->p);
	}
}

/**
 * JPacket dispatcher that dispatches decoded java packets
 */
void cb_pcap_packet_dispatch(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	printf("cb_pcap_packet_dispatch() - ENTER\n"); fflush(stdout);

	cb_packet_t *data = (cb_packet_t *)user;

	JNIEnv *env = data->env;

	jmemoryPeer(env, data->header, pkt_header, sizeof(pcap_pkthdr), data->pcap);
	jmemoryPeer(env, data->packet, pkt_data, pkt_header->caplen, data->pcap);

	printf("cb_pcap_packet_dispatch() - Java_org_jnetpcap_packet_JScanner_scan\n"); fflush(stdout);

	if (Java_org_jnetpcap_packet_JScanner_scan(
			env,
			data->scanner,
			data->packet,
			data->state,
			data->id,
			pkt_header->len) < 0) {
		return;
	}

	printf("cb_pcap_packet_dispatch() - transferToNewBuffer\n"); fflush(stdout);

	jobject pcap_packet =
		transferToNewBuffer(env, pkt_header, pkt_data, data->state);
	if (pcap_packet == NULL) {
		if (data->pcap != NULL) {
			pcap_breakloop(data->p);
		} else {
			data->flags |= DEBUG_INJECT_PACKET_BREAK_LOOP;
		}
		return;
	}

	printf("cb_pcap_packet_dispatch() - CallVoidMethod\n"); fflush(stdout);

	jobject obj = data->obj;
	jmethodID mid = data->mid;

	printf("cb_pcap_packet_dispatch() - obj=%p, mid=%p, pcap_packet=%p, user=%p\n",
			obj,
			mid,
			pcap_packet,
			data->user); fflush(stdout);

	env->CallVoidMethod(
			data->obj,
			data->mid,
			pcap_packet,
			data->user);
//			NULL,
//			NULL);


	printf("cb_pcap_packet_dispatch() - DeleteLocalRef\n"); fflush(stdout);

	env->DeleteLocalRef(pcap_packet);

	printf("cb_pcap_packet_dispatch() - ExceptionCheck\n"); fflush(stdout);

	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
		pcap_breakloop(data->p);
	}
}


/**
 * Specialized handler that natively dumps to a dump handle without entering
 * java environment.
 */
void cb_pcap_dumper_handler(u_char *dump_handle, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	pcap_dump(dump_handle, pkt_header, pkt_data);
}


/**
 * Copies contents of a libpcap capture header, scanner packet_t structure and
 * libpcap provided packet data buffer into a single newly allocated memory block
 * peered to brand new PcapPacket.
 *
 * @param env
 *        JNI environment
 * @param pkt_header
 *        libpcap provided capture header
 * @param pkt_data
 *        libpcap provided data buffer containing captured packet
 * @param state
 *        a java object reference to JPacket.State which was initialized by
 *        the scanner
 * @return
 *        A new packet object owner of a newly malloced block of memory which
 *        contains a copy of pcap header, packet state and packet data buffer
 *        and is fully initialized.
 */
jobject transferToNewBuffer(
		JNIEnv *env,
		const pcap_pkthdr *pkt_header,
		const u_char *pkt_data,
		jobject state) {

	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, state);
	size_t state_size =
		packet->pkt_header_count * sizeof(header_t) +
		sizeof(packet_state_t);

	size_t size = pkt_header->caplen + state_size + sizeof(pcap_pkthdr);
	if (size > (1024 * 1024)) {
		throwException(env, ILLEGAL_STATE_EXCEPTION,
				"packet size over 1MB\n");
		return NULL;
	}


	jobject pcap_packet = env->NewObject(
			pcapPacketClass,
			pcapPacketConstructorMID,
			jmemoryPOINTER_CONST);
	if (pcap_packet == NULL) {
		throwException(env, ILLEGAL_STATE_EXCEPTION,
				"unable to allocate PcapPacket object");
		return NULL;
	}

	jobject jheader = env->GetObjectField(pcap_packet, pcapHeaderFID);
	jobject jstate = env->GetObjectField(pcap_packet, pcapStateFID);
	if (jheader == NULL || jstate == NULL) {
		throwException(env, ILLEGAL_STATE_EXCEPTION,
				"unable to allocate PcapHeader object");
		return NULL;
	}

	char *ptr = jmemoryAllocate(env, size, jheader);
	if (ptr == NULL) {
		throwVoidException(env, OUT_OF_MEMORY_ERROR);
		return NULL;
	}


	memcpy(ptr, pkt_header, sizeof(pcap_pkthdr));
	jmemoryResize(env, jheader, sizeof(pcap_pkthdr));
	ptr += sizeof(pcap_pkthdr);
	
	memcpy(ptr, pkt_data, pkt_header->caplen);
	jmemoryPeer(env, pcap_packet, ptr, pkt_header->caplen, jheader);
	ptr += pkt_header->caplen + (pkt_header->caplen % 8);

	memcpy(ptr, packet, state_size);
	jmemoryPeer(env, jstate, ptr, state_size, jheader);
	ptr += state_size;

	/*
	 * Free up intermediate local references. We can't rely on JNI freeing them
	 * since we may be called from a long or infinite loop. JNI references are
	 * only freeded up when main JNI call returns which may be never in our case.
	 */
	env->DeleteLocalRef(jheader);
	env->DeleteLocalRef(jstate);

	/* Local reference is good enough for return value. If this is returned from
	 * JNI code upto java, JNI turns them into globs.
	 */
	return pcap_packet;
}

