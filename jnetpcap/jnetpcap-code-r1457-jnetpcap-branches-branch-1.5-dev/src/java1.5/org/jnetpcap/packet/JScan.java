/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;

// TODO: Auto-generated Javadoc
/**
 * A inprogress working scan structure. Used by JScanner to pass around
 * information between various scan routines. This class is peered with scan_t
 * structure that is used to pass information both between native header
 * scanners and java scanners.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JScan
    extends
    JStruct {

	/** The Constant STRUCT_NAME. */
	private static final String STRUCT_NAME = "scan_t";

	/**
	 * Special header ID that when used with a scanner's next_id variable,
	 * indicates that this is the last header and scanner should exit its loop.
	 * The constant can be used both in java and in JNI code.
	 */
	public final static int END_OF_HEADERS_ID = -1;

	/**
	 * Alocates and creates scan_t structure in native memory.
	 */
	public JScan() {
		super(STRUCT_NAME, sizeof());
	}

	/**
	 * Creates an uninitialized scan structure.
	 * 
	 * @param type
	 *          memory type
	 */
	public JScan(Type type) {
		super(STRUCT_NAME, type);
	}

	/**
	 * Scan_id.
	 * 
	 * @return the int
	 */
	public native int scan_id();

	/**
	 * Scan_next_id.
	 * 
	 * @return the int
	 */
	public native int scan_next_id();

	/**
	 * Scan_length.
	 * 
	 * @return the int
	 */
	public native int scan_length();

	/**
	 * Scan_id.
	 * 
	 * @param id
	 *          the id
	 */
	public native void scan_id(int id);

	/**
	 * Scan_next_id.
	 * 
	 * @param next_id
	 *          the next_id
	 */
	public native void scan_next_id(int next_id);

	/**
	 * Scan_length.
	 * 
	 * @param length
	 *          the length
	 */
	public native void scan_length(int length);
	
	/**
	 * Scan_prefix.
	 * 
	 * @return the int
	 */
	public native int scan_prefix();
	
	/**
	 * Scan_gap.
	 * 
	 * @return the int
	 */
	public native int scan_gap();
	
	/**
	 * Scan_payload.
	 * 
	 * @return the int
	 */
	public native int scan_payload();
	
	/**
	 * Scan_postix.
	 * 
	 * @return the int
	 */
	public native int scan_postix();

	/**
	 * Record_header.
	 * 
	 * @return the int
	 */
	public native int record_header();

	
	/**
	 * Scan_prefix.
	 * 
	 * @param value
	 *          the value
	 */
	public native void scan_prefix(int value);
	
	/**
	 * Scan_gap.
	 * 
	 * @param value
	 *          the value
	 */
	public native void scan_gap(int value);
	
	/**
	 * Scan_payload.
	 * 
	 * @param value
	 *          the value
	 */
	public native void scan_payload(int value);
	
	/**
	 * Scan_postix.
	 * 
	 * @param value
	 *          the value
	 */
	public native void scan_postix(int value);

	/**
	 * Record_header.
	 * 
	 * @param value
	 *          the value
	 */
	public native void record_header(int value);

	/**
	 * Sets all the various lengths in the header structure all at once.
	 * 
	 * @param prefix
	 *          prefix length in bytes before the header
	 * @param header
	 *          length of the header (same as {@link #scan_length(int)})
	 * @param gap
	 *          length of the gap between header and payload
	 * @param payload
	 *          length of payload
	 * @param postfix
	 *          length of postfix after the payload
	 */
	public native void scan_set_lengths(
	    int prefix,
	    int header,
	    int gap,
	    int payload,
	    int postfix);

	/**
	 * Size in bytes of the native scan_t structure on this particular platform.
	 * 
	 * @return size in bytes
	 */
	public native static int sizeof();

	/**
	 * Gets the current packet data buffer.
	 * 
	 * @param buffer
	 *          packet data buffer
	 */
	public native void scan_buf(JBuffer buffer);

	/**
	 * Size of packet data.
	 * 
	 * @param size
	 *          length in bytes
	 */
	public native void scan_buf_len(int size);

	/**
	 * Sets the current offset by the scanner into the packet buffer.
	 * 
	 * @param offset
	 *          offset in bytes
	 */
	public native void scan_offset(int offset);

	/**
	 * Java packet that is being processed.
	 * 
	 * @return the packet instance being currently processed
	 */
	public native JPacket scan_packet();

	/**
	 * Gets teh curren offset by the dscanner into the packet buffer.
	 * 
	 * @return offset in bytes
	 */
	public native int scan_offset();
}
