/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdint.h>
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

#include "packet_jscanner.h"
#include "packet_protocol.h"
#include "jnetpcap_utils.h"
#include "nio_jmemory.h"
#include "nio_jbuffer.h"
#include "org_jnetpcap_protocol_JProtocol.h"
#include "org_jnetpcap_nio_JMemoryReference.h"
#include "org_jnetpcap_packet_JScanner.h"
#include "org_jnetpcap_packet_JScannerReference.h"
#include "export.h"
#include "util_debug.h"

//#define DEBUG

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/
char str_buf[1024];
char id_str_buf[256];

/*****
 * Temporarily backout of C++ Debug class and g++ compiler
 * 
 Debug scanner_logger("jscanner");
 Debug protocol_logger("jprotocol", &scanner_logger);
 ************/

/* scanner specific debug_ trace functions */
void debug_header(char *msg, header_t *header) {
	debug_trace(msg,
			"id=%s prefix=%-3d header=%-3d gap=%-3d payload=%-3d post=%-3d",
			id2str(header->hdr_id), header->hdr_prefix, header->hdr_length,
			header->hdr_gap, header->hdr_payload, header->hdr_postfix);
}

void debug_scan(char *msg, scan_t *scan) {
	debug_trace(msg,
			"id=%s off=%d prefix=%-3d header=%-3d gap=%-3d payload=%-3d post=%-3d "
				"nid=%s buf_len=%-3d wire_len=%-3d flags=%0x",
			id2str(scan->id), scan->offset, scan->hdr_prefix, scan->length,
			scan->hdr_gap, scan->hdr_payload, scan->hdr_postfix, id2str(
					scan->next_id), scan->buf_len, scan->wire_len,
			scan->scanner->sc_flags[scan->id]);
}

/**
 * Checks if the data at specified offset is accessible or has it possibly
 * been truncated.
 */
int is_accessible(scan_t *scan, int offset) {
	return (scan->offset + offset) <= scan->buf_len;
}
/*
 * Converts our numerical header ID to a string, which is better suited for
 * debugging.
 */
const char *id2str(int id) {

	if (id == END_OF_HEADERS) {
		return "END_OF_HEADERS";

	} else if (native_protocol_names[id] != NULL) {
		return native_protocol_names[id];

	} else {
		sprintf(id_str_buf, "%d", id);

		return id_str_buf;
	}
}

/**
 * Scan packet buffer
 */
int scan(JNIEnv *env, jobject obj, jobject jpacket, scanner_t *scanner,
		packet_state_t *p_packet, int first_id, char *buf, int buf_len,
		uint32_t wirelen) {

	scan_t scan; // Our current in progress scan's state information
	scan_t *pscan = &scan;
	scan.env = env;
	scan.jscanner = obj;
	scan.jpacket = jpacket;
	scan.scanner = scanner;
	scan.packet = p_packet;
	scan.header = &p_packet->pkt_headers[0];
	scan.buf = buf;
	scan.buf_len = buf_len; // Changing buffer length, reduced by 'postfix'
	scan.mem_len = buf_len; // Constant in memory buffer length
	scan.wire_len = wirelen;
	scan.offset = 0;
	scan.length = 0;
	scan.id = first_id;
	scan.next_id = PAYLOAD_ID;
	scan.flags = 0;
	scan.stack_index = 0;

	scan.hdr_count = 0;
	scan.hdr_flags = 0;
	scan.hdr_prefix = 0;
	scan.hdr_gap = 0;
	scan.hdr_payload = 0;
	scan.hdr_postfix = 0;

	memset(scan.header, 0, sizeof(header_t));

	// Point jscan 
	setJMemoryPhysical(env, scanner->sc_jscan, toLong(&scan));

	// Local temp variables
	register uint64_t mask;

#ifdef DEBUG
	debug_enter("scan");
	debug_trace("processing packet", "#%d", p_packet->pkt_frame_num);
#endif

	/*
	 * Main scanner loop, 1st scans for builtin header types then
	 * reverts to calling on JBinding objects to provide the binding chain
	 */
	while (scan.id != END_OF_HEADERS) {
#ifdef DEBUG
		debug_trace("", "");
		debug_trace("processing header", id2str(scan.id));
		debug_scan("loop-top", &scan);
#endif

		/* A flag that keeps track of header recording. Set in record_header()*/
		scan.is_recorded = 0;

		/*
		 * If debugging is compiled in, we can also call on each protocols
		 * debug_* function to print out details about the protocol header
		 * structure. 
		 */
#ifdef DEBUG
		if (native_debug[scan.id]) {
			native_debug[scan.id](scan.buf + scan.offset);
		}
#endif

		/* 
		 * Scan of each protocol is done through a dispatch function table.
		 * Each protocol that has a protocol header scanner attached, a scanner
		 * designed specifically for that protocol. The protocol id is also the
		 * index into the table. There are 2 types of scanners both have exactly
		 * the same signature and thus both are set in this table. The first is
		 * the native scanner that only performs a direct scan of the header.
		 * The second scanner is a java header scanner. It is based on 
		 * JHeaderScanner class. A single dispatch method callJavaHeaderScanner
		 * uses the protocol ID to to dispatch to the appropriate java scanner.
		 * Uses a separate java specific table: sc_java_header_scanners[]. The
		 * java scanner is capable of calling the native scan method from java
		 * but also adds the ability to check all the attached JBinding[] for
		 * any additional registered bindings. Interesting fact is that if the
		 * java scanner doesn't have any bindings nor does it override the 
		 * default scan method to perform a scan in java and is also setup to 
		 * dispatch to native scanner, it is exactly same thing as if the 
		 * native scanner was dispatched directly from here, but round 
		 * about way through java land.
		 */
		if (scanner->sc_scan_table[scan.id] != NULL) {
			scanner->sc_scan_table[scan.id](&scan); // Dispatch to scanner
		}

#ifdef DEBUG
		debug_scan("loop-middle", &scan);
#endif

		if (scan.length == 0) {
#ifdef DEBUG
			debug_scan("loop-length==0", &scan);
#endif
			if (scan.id == PAYLOAD_ID) {
				if (scan.stack_index == 0) {
					scan.next_id = END_OF_HEADERS;
				} else {
					scan.stack_index --;
					scan.next_id = scan.stack[scan.stack_index].next_id;
					scan.offset = scan.stack[scan.stack_index].offset;
				}
			} else {
				scan.next_id = PAYLOAD_ID;
			}

		} else { // length != 0

#ifdef DEBUG
			debug_scan("loop-length > 0", &scan);
#endif

			/******************************************************
			 * ****************************************************
			 * * If override flag is set, then we reset the
			 * * discovered next protocol. If that is what the user 
			 * * wants then that is what he gets.
			 * ****************************************************
			 ******************************************************/
			if (scanner->sc_flags[scan.id] & FLAG_OVERRIDE_BINDING) {
#ifdef DEBUG
				debug_scan("TCP OVERRIDE", &scan);
#endif
				scan.next_id = PAYLOAD_ID;
			}

			/******************************************************
			 * ****************************************************
			 * * Now do HEURISTIC discovery scans if the appropriate
			 * * flags are set. Heuristics allow us to provide nxt
			 * * protocol binding, using discovery (an educated 
			 * * guess). 
			 * ****************************************************
			 ******************************************************/
			if (scanner->sc_flags[scan.id] & FLAG_HEURISTIC_BINDING) {

				/* 
				 * Save these critical properties, in case heuristic changes them
				 * for this current header, not the next one its supposed to
				 * check for.
				 */
				int saved_offset = scan.offset;
				int saved_length = scan.length;

				/* Advance offset to next header, so that heuristics can get a 
				 * peek. It will be restored at the end of heuristics block.
				 */
				scan.offset += scan.length + scan.hdr_gap;

				/*
				 * 2 types of heuristic bindings. Pre and post.
				 * Pre - heuristics are run before the direct discovery method
				 *       in scanner. Only after the pre-heuristic fail do we
				 *       utilize the directly discovered binding.
				 * 
				 * Post - heuristics are run after the direct discovery method
				 *        didn't produce a binding.
				 *
				 * ------------------------------------------------------------
				 * 
				 * In our case, since we have already ran the direct discovery
				 * in the header scanner, we save scan.next_id value, reset it,
				 * call the heuristic function, check its scan.next_id if it
				 * was set, if it was, then use that instead. Otherwise if it
				 * wasn't restore the original next_id and continue on normally.
				 */
				if (scanner->sc_flags[scan.id] & FLAG_HEURISTIC_PRE_BINDING) {
#ifdef DEBUG
					debug_scan("heurists_pre", &scan);
#endif

					int saved_next_id = scan.next_id;
					scan.next_id = PAYLOAD_ID;

					for (int i = 0; i < MAX_ID_COUNT; i++) {
						native_validate_func_t validate_func;
						validate_func
								= scanner->sc_heuristics_table[scan.id][i];

						if (validate_func == NULL) {
							break;
						}

						if ((scan.next_id = validate_func(&scan)) != INVALID) {
							break;
						}
					}

					if (scan.next_id == PAYLOAD_ID) {
						scan.next_id = saved_next_id;
					}

				} else if (scan.next_id == PAYLOAD_ID) {
#ifdef DEBUG
					debug_scan("heurists_post", &scan);
#endif
					for (int i = 0; i < MAX_ID_COUNT; i++) {
						native_validate_func_t validate_func;
						validate_func
								= scanner->sc_heuristics_table[scan.id][i];

						if (validate_func == NULL) {
							break;
						}

#ifdef DEBUG
						debug_trace("heurists_post", "[%d]", i);
#endif
						if ((scan.next_id = validate_func(&scan)) != INVALID) {

#ifdef DEBUG
							debug_scan("heurists_post::found", &scan);
#endif

							break;
						}
					}
				}

				/* Restore these 2 critical properties */
				scan.offset = saved_offset;
				scan.length = saved_length;
			}

			/******************************************************
			 * ****************************************************
			 * * Now record discovered information in structures
			 * ****************************************************
			 ******************************************************/
			record_header(&scan);

#ifdef DEBUG
			debug_header("header_t", scan.header - 1);
#endif
		} // End if len != 0

#ifdef DEBUG
		debug_scan("loop-bottom", &scan);
#endif

		scan.id = scan.next_id;
		scan.offset += scan.length + scan.hdr_gap;
		scan.length = 0;
		scan.next_id = PAYLOAD_ID;

		if (scan.offset >= scan.buf_len) {
			scan.id = END_OF_HEADERS;
		}

	} // End for loop

	/* record number of header entries found */
	//	scan.packet->pkt_header_count = count;

	process_flow_key(&scan);

#ifdef DEBUG
	debug_trace("loop-finished",
			"header_count=%d offset=%d header_map=0x%X",
			scan.packet->pkt_header_count, scan.offset,
			scan.packet->pkt_header_map);
	debug_exit("scan()");
#endif

	return scan.offset;
} // End scan()

/**
 * Record state of the header in the packet state structure.
 */
void record_header(scan_t *scan) {

#ifdef DEBUG
	debug_enter("record_header");
	debug_scan("top", scan);
#endif

	/*
	 * Check if already recorded
	 */
	if (scan->is_recorded) {
#ifdef DEBUG
		debug_exit("record_header");
#endif
		return;
	}

	register int offset = scan->offset;
	register header_t *header = scan->header;
	register int buf_len = scan->buf_len;
	packet_state_t *packet = scan->packet;

	/*
	 * Decrease wire-length by postfix amount so that next header's payload
	 * will be reduced and won't go over this header's postfix
	 */
	scan->wire_len -= scan->hdr_postfix;
	if (buf_len > scan->wire_len) {
		buf_len = scan->buf_len = scan->wire_len; // Make sure that buf_len and wire_len sync up
#ifdef DEBUG
		debug_scan("adj buf_len", scan);
#endif
	}

	/*
	 * If payload length hasn't explicitly been set to some length, set it
	 * to the remainder of the packet.
	 */
	if (scan->hdr_payload == 0 && scan->id != PAYLOAD_ID) {
		scan->hdr_payload = scan->buf_len - (offset + scan->hdr_prefix
				+ scan->length + scan->hdr_gap);
		scan->hdr_payload = (scan->hdr_payload < 0) ? 0 : scan->hdr_payload;
#ifdef DEBUG
		debug_scan("adj payload", scan);
#endif
	}

	adjustForTruncatedPacket(scan);
	register int length = scan->length;

	/*
	 * Initialize the header entry in our packet header array
	 */
//	packet->pkt_header_map |= (uint64_t)(1ULL << scan->id);
	PACKET_STATE_ADD_HEADER(packet, scan->id);
	header->hdr_id = scan->id;
	header->hdr_offset = offset + scan->hdr_prefix;
	header->hdr_analysis = NULL;

	/*
	 * This is a combination of regular header flags with cumulative flags
	 * which are accumulated by subsequent pass to the next header and pass on
	 * to their encapsulated headers. This is a way to pass flags such as 
	 * the remaining header's are fragmented.
	 */
	header->hdr_flags = scan->hdr_flags | (scan->flags & CUMULATIVE_FLAG_MASK);

	header->hdr_prefix = scan->hdr_prefix;
	header->hdr_gap = scan->hdr_gap;
	header->hdr_payload = scan->hdr_payload;
	header->hdr_postfix = scan->hdr_postfix;
	header->hdr_length = length;

	scan->hdr_flags = 0;
	scan->hdr_prefix = 0;
	scan->hdr_gap = 0;
	scan->hdr_payload = 0;
	scan->hdr_postfix = 0;
	scan->is_recorded = 1;
	scan->hdr_count ++;

	packet->pkt_header_count++; /* number of entries */

	//	scan->id = -1; // Indicates, that header is already recorded

	/* Initialize key fields in a new header */
	header = ++scan->header; /* point to next header entry *** ptr arithmatic */
	memset(header, 0, sizeof(header_t));

#ifdef DEBUG
	debug_scan("bottom", scan);
	debug_exit("record_header");
#endif
}

/**
 * Adjusts for a packet that has been truncated. Sets appropriate flags in the
 * header flags field, resets lengths of prefix, header, gap, payload and 
 * postfix appropriately to account for shortened packet.
 */
void adjustForTruncatedPacket(scan_t *scan) {
#ifdef DEBUG
	debug_enter("adjustForTruncatedPacket");
	debug_trace("packet", "%ld", scan->scanner->sc_cur_frame_num);
#endif

	/*
	 * Adjust for truncated packets. We check the end of the header record
	 * against the buf_len. If the end is past the buf_len, that means that we
	 * need to start trucating in the following order: 
	 * postfix, payload, gap, header, prefix
	 * 
	 * +-------------------------------------------+
	 * | prefix | header | gap | payload | postfix |
	 * +-------------------------------------------+
	 * 
	 */
	register int start = scan->offset + scan->hdr_prefix + scan->length
			+ scan->hdr_gap + scan->hdr_payload;

	register int end = start + scan->hdr_postfix;
	register int buf_len = scan->buf_len;

#ifdef DEBUG
	debug_scan((char *)id2str(scan->id), scan);
	debug_trace(id2str(scan->id), "offset=%d, pre=%d, len=%d, gap=%d, pay=%d, post=%d",
			scan->offset,
			scan->hdr_prefix,
			scan->length,
			scan->hdr_gap,
			scan->hdr_payload,
			scan->hdr_postfix);
	debug_trace(id2str(scan->id), "start=%d end=%d buf_len=%d", start, end, buf_len);
#endif

	if (end > buf_len) { // Check if postfix extends past the end of packet

		/*
		 * Because postfix is at the end, whenever the packet is truncated
		 * postfix is always truncated, unless it wasn't set
		 */
		if (scan->hdr_postfix > 0) {
			scan->hdr_flags |= HEADER_FLAG_PREFIX_TRUNCATED;
			scan->hdr_postfix = (start > scan->mem_len) ? 0 : scan->mem_len
					- start;
			scan->hdr_postfix = (scan->hdr_postfix < 0) ? 0 : scan->hdr_postfix;
#ifdef DEBUG
			debug_scan("adjust postfix", scan);
#endif
		}

		/* Position at payload and process */
		start -= scan->hdr_payload;
		end = start + scan->hdr_payload;

		if (end > buf_len) {
			scan->hdr_flags |= HEADER_FLAG_PAYLOAD_TRUNCATED;
			scan->hdr_payload = (start > buf_len) ? 0 : buf_len - start;
			scan->hdr_payload = (scan->hdr_payload < 0) ? 0 : scan->hdr_payload;

#ifdef DEBUG
			debug_scan("adjust payload", scan);
			debug_trace("adjust payload", "start=%d end=%d", start, end);
#endif

			/* Position at gap and process */
			start -= scan->hdr_gap;
			end = start + scan->hdr_gap;
			if (scan->hdr_gap > 0 && end > buf_len) {

				scan->hdr_flags |= HEADER_FLAG_GAP_TRUNCATED;
				scan->hdr_gap = (start > buf_len) ? 0 : buf_len - start;
				scan->hdr_gap = (scan->hdr_gap < 0) ? 0 : scan->hdr_gap;
#ifdef DEBUG
				debug_scan("adjust gap", scan);
#endif
			}

			/* Position at header and process */
			start -= scan->length;
			end = start + scan->length;

			if (end > buf_len) {
				scan->hdr_flags |= HEADER_FLAG_HEADER_TRUNCATED;
				scan->length = (start > buf_len) ? 0 : buf_len - start;
				scan->length = (scan->length < 0) ? 0 : scan->length;
#ifdef DEBUG
				debug_scan("adjust header", scan);
#endif

				/* Position at prefix and process */
				start -= scan->hdr_prefix;
				end = start + scan->hdr_prefix;

				if (0 && scan->hdr_prefix > 0 && end > buf_len) {
					scan->hdr_flags |= HEADER_FLAG_PREFIX_TRUNCATED;
					scan->hdr_prefix = (start > buf_len) ? 0 : buf_len - start;
					scan->hdr_prefix = (scan->hdr_prefix < 0) ? 0
							: scan->hdr_prefix;
#ifdef DEBUG
					debug_scan("adjust prefix", scan);
#endif

				}
			}
		}
	}

#ifdef DEBUG
	debug_exit("adjustForTruncatedPacket");
#endif
#undef DEBUG
}

/**
 * Scan packet buffer by dispatching to JBinding java objects
 */
void callJavaHeaderScanner(scan_t *scan) {

#ifdef DEBUG
	debug_enter("callJavaHeaderScanner");
#endif
	JNIEnv *env = scan->env;
	jobject jscanner = scan->scanner->sc_java_header_scanners[scan->id];

	if (jscanner == NULL) {
		sprintf(str_buf, "java header scanner not set for ID=%d (%s)",
				scan->id, id2str(scan->id));
#ifdef DEBUG
		debug_error("callJavaHeaderScanner()", str_buf);
#endif
		throwException(scan->env, NULL_PTR_EXCEPTION, str_buf);
		return;
	}

	env->CallVoidMethod(jscanner, scanHeaderMID, scan->scanner->sc_jscan);

#ifdef DEBUG
	debug_exit("callJavaHeaderScanner");
#endif
}

/**
 * Prepares a scan of packet buffer
 */
int scanJPacket(JNIEnv *env, jobject obj, jobject jpacket, jobject jstate,
		scanner_t *scanner, int first_id, char *buf, int buf_length,
		uint32_t wirelen) {

#ifdef DEBUG
	debug_enter("scanJPacket");
#endif

	/* Check if we need to wrap our entry buffer around */
	if (scanner->sc_offset > scanner->sc_len - sizeof(header_t)
			* MAX_ENTRY_COUNT) {
		scanner->sc_offset = 0;
	}

	packet_state_t *packet = (packet_state_t *) (((char *) scanner->sc_packet)
			+ scanner->sc_offset);

	/*
	 * Peer JPacket.state to packet_state_t structure
	 */
	//	setJMemoryPhysical(env, jstate, toLong(packet));
	//	env->SetObjectField(jstate, jmemoryKeeperFID, obj); // Set it to JScanner
	jmemoryPeer(env, jstate, packet, sizeof(packet_state_t), obj);

	/*
	 * Reset the entire packet_state_t structure
	 */
	memset(packet, 0, sizeof(packet_state_t));

	/* 
	 * Initialize the packet_state_t structure for new packet entry. We need to 
	 * initialize everything since we may be wrapping around and writting over 
	 * previously stored data.
	 */
	packet->pkt_header_count = 0;
	packet->pkt_frame_num = scanner->sc_cur_frame_num++;
	packet->pkt_wirelen = (uint32_t) wirelen;
	packet->pkt_caplen = (uint32_t) buf_length;
	packet->pkt_flags = 0;

	if (buf_length != wirelen) {
		packet->pkt_flags |= PACKET_FLAG_TRUNCATED;
	}

#ifdef DEBUG
	debug_trace("before scan", "buf_len=%d wire_len=%d", buf_length, wirelen);
#endif

	scan(env, obj, jpacket, scanner, packet, first_id, buf, buf_length, wirelen);

#ifdef DEBUG
	debug_trace("after scan", "buf_len=%d wire_len=%d", buf_length, wirelen);
#endif

	const size_t len = sizeof(packet_state_t) + (sizeof(header_t)
			* packet->pkt_header_count);

	scanner->sc_offset += len;

	jmemoryResize(env, jstate, len);

#ifdef DEBUG
	debug_exit("scanJPacket");
#endif

}

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

jclass jheaderScannerClass = NULL;

jmethodID scanHeaderMID = 0;

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    initIds
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_initIds
(JNIEnv *env, jclass clazz) {

	if ( (jheaderScannerClass = findClass(
							env,
							"org/jnetpcap/packet/JHeaderScanner")) == NULL) {
		return;
	}

	if ( (scanHeaderMID = env->GetMethodID(
							jheaderScannerClass,
							"scanHeader",
							"(Lorg/jnetpcap/packet/JScan;)V")) == NULL) {
		return;
	}

	/*
	 * Initialize the global native scan function dispatch table.
	 * i.e. scan_ethernet(), scan_ip4(), etc...
	 */
	init_native_protocols();
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScanner_sizeof(JNIEnv *env,
		jclass obj) {
	return (jint) sizeof(scanner_t);
}

/*
 * Class:     org_jnetpcap_packet_JScannerReference
 * Method:    disposeNative
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScannerReference_disposeNative
(JNIEnv *env, jobject obj, jlong size) {

	jlong pt = env->GetLongField(obj, jmemoryRefAddressFID);
	scanner_t *scanner = (scanner_t *)toPtr(pt);
	if (scanner == NULL) {
		return;
	}

	env->DeleteGlobalRef(scanner->sc_jscan);
	scanner->sc_jscan = NULL;

	if (scanner->sc_subheader != NULL) {
		free(scanner->sc_subheader);
		scanner->sc_subheader = NULL;
	}

	for (int i = 0; i < MAX_ID_COUNT; i ++) {
		if (scanner->sc_java_header_scanners[i] != NULL) {
			env->DeleteGlobalRef(scanner->sc_java_header_scanners[i]);
			scanner->sc_java_header_scanners[i] = NULL;
		}
	}

	/*
	 * Same as super.dispose(): call from JScannerReference.dispose for
	 * JMemoryReference.super.dispose.
	 */
//	Java_org_jnetpcap_nio_JMemoryReference_disposeNative0(env, obj, pt, size);
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    getFrameNumber
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_packet_JScanner_getFrameNumber(
		JNIEnv *env, jobject obj) {

	scanner_t *scanner = (scanner_t *) getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return -1;
	}

	return (jlong) scanner->sc_cur_frame_num;
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    init
 * Signature: (Lorg.jnetpcap.packet.JScan;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_init
(JNIEnv *env, jobject obj, jobject jscan) {

#ifdef DEBUG
	debug_enter("JScanner_init");
#endif
	if (jscan == NULL) {
		throwException(env, NULL_PTR_EXCEPTION,
				"JScan parameter can not be null");
		return;
	}

	void *block = (char *)getJMemoryPhysical(env, obj);
	size_t size = (size_t)env->GetIntField(obj, jmemorySizeFID);

	memset(block, 0, size);

	scanner_t *scanner = (scanner_t *)block;
	scanner->sc_jscan = env->NewGlobalRef(jscan);
	scanner->sc_len = size - sizeof(scanner_t);
	scanner->sc_offset = 0;
	scanner->sc_packet = (packet_state_t *)((char *)block + sizeof(scanner_t));

	for (int i = 0; i < MAX_ID_COUNT; i++) {
		scanner->sc_scan_table[i] = native_protocols[i];
	}

	for (int i = 0; i < MAX_ID_COUNT; i++) {
		for (int j = 0; j < MAX_ID_COUNT; j++) {
			scanner->sc_heuristics_table[i][j] = native_heuristics[i][j];
		}
	}

	/* Initialize sub-header area - allocate 1/10th */
	scanner->sc_sublen = size / 10;
	scanner->sc_subindex = 0;
	scanner->sc_subheader = (header_t *)malloc(scanner->sc_sublen);

#ifdef DEBUG
	debug_exit("JScanner_init");
#endif

}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    loadScanners
 * Signature: (I[Lorg/jnetpcap/packet/JHeaderScanner;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_loadScanners
(JNIEnv *env, jobject obj, jobjectArray jascanners) {

#ifdef DEBUG
	debug_enter("loadScanners");
#endif

	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	jsize size = env->GetArrayLength(jascanners);

#ifdef DEBUG
	debug_trace("load", "loaded %d scanners", (int)size);
#endif

	if (size != MAX_ID_COUNT) {
		throwException(env,
				ILLEGAL_ARGUMENT_EXCEPTION,
				"size of array must be MAX_ID_COUNT size");
#ifdef DEBUG
		debug_error("IllegalArgumentException",
				"size of array must be MAX_ID_COUNT size");
#endif
		return;
	}

	for (int i = 0; i < MAX_ID_COUNT; i ++) {
		jobject loc_ref = env->GetObjectArrayElement(jascanners, (jsize) i);
		if (loc_ref == NULL) {

			/*
			 * If we don't have a java header scanner, then setup the native
			 * scanner in its place. Any unused java scanner slot will be filled
			 * with native scanner.
			 */
			scanner->sc_scan_table[i] = native_protocols[i];
			//			printf("loadScanners::native(%s)\n", id2str(i));fflush(stdout);
		} else {

			//			printf("loadScanners::java(%s)\n", id2str(i));fflush(stdout);


			if (scanner->sc_java_header_scanners[i] != NULL) {
				env->DeleteGlobalRef(scanner->sc_java_header_scanners[i]);
				scanner->sc_java_header_scanners[i] = NULL;
			}

			/*
			 * Record the java header scanner and replace the native scanner with
			 * our java scanner in dispatch table.
			 */
			scanner->sc_java_header_scanners[i] = env->NewGlobalRef(loc_ref);
			scanner->sc_scan_table[i] = callJavaHeaderScanner;

			env->DeleteLocalRef(loc_ref);
		}
	}

#ifdef DEBUG
	debug_exit("loadScanners");
#endif

}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    loadFlags
 * Signature: ([I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_loadFlags
(JNIEnv *env, jobject obj, jintArray jflags) {
#ifdef DEBUG
	debug_enter("loadFlags");
#endif

	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	jsize size = env->GetArrayLength(jflags);

#ifdef DEBUG
	debug_trace("load", "loaded %d flags", (int)size);
#endif

	if (size != MAX_ID_COUNT) {
		throwException(env,
				ILLEGAL_ARGUMENT_EXCEPTION,
				"size of array must be MAX_ID_COUNT size");
#ifdef DEBUG
		debug_error("IllegalArgumentException",
				"size of array must be MAX_ID_COUNT size");
#endif
		return;
	}

	env->GetIntArrayRegion(jflags, 0, size, (jint *)scanner->sc_flags);

#ifdef DEBUG
	debug_exit("loadFlags");
#endif
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    scan
 * Signature: (Lorg/jnetpcap/packet/JPacket;Lorg/jnetpcap/packet/JPacket$State;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScanner_scan(JNIEnv *env,
		jobject obj, jobject jpacket, jobject jstate, jint id, jint wirelen) {

	scanner_t *scanner = (scanner_t *) getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return -1;
	}

	char *buf = (char *) getJMemoryPhysical(env, jpacket);
	if (buf == NULL) {
		return -1;
	}

	int size = (int) env->GetIntField(jpacket, jmemorySizeFID);

	if (wirelen < size) {
		throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "wirelen < buffer len");
		return -1;
	}

	return scanJPacket(env, obj, jpacket, jstate, scanner, id, buf, size,
			(uint32_t) wirelen);
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    setFrameNumber
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_setFrameNumber
(JNIEnv *env, jobject obj, jlong frame_no) {

	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	scanner->sc_cur_frame_num = (uint64_t) frame_no;

	return;
}
