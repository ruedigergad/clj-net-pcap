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
package org.jnetpcap;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;

// TODO: Auto-generated Javadoc
/**
 * <pre>
 * struct pkt_header {
 *  struct timeval ts; // ts.tv_sec, ts.tv_usec
 *  uint32 caplen;     // captured length
 *  uint32 len;        // original length
 * }
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapHeader
    extends
    JStruct implements JCaptureHeader {

	/** Name of the native structure. */
	public static final String STRUCT_NAME = "pcap_pkthdr";

	/**
	 * Size of the pcap_pkthdr structure in bytes.
	 * 
	 * @return size of structure
	 */
	public native static int sizeof();

	/**
	 * Length of the libpcap pcap header in bytes. This may differ from what
	 * <code>sizeof()</code> method returns due to native compiler padding for
	 * byte aligment.
	 */
	public final static int LENGTH = 16;

	/**
	 * Creates a header structure with allocated memory. All fields are
	 * initialized to defaults.
	 */
	public PcapHeader() {
		super(STRUCT_NAME, LENGTH);
	}

	/**
	 * Creates a header structure with initial values.
	 * 
	 * @param caplen
	 *          buffer size
	 * @param wirelen
	 *          original packet length
	 */
	public PcapHeader(int caplen, int wirelen) {
		super(STRUCT_NAME, LENGTH);

		hdr_len(caplen);
		hdr_wirelen(wirelen);

		long t = System.currentTimeMillis();
		long s = t / 1000;
		long us = (t - s * 1000) * 1000;

		hdr_sec(s);
		hdr_usec((int) us);
	}

	/**
	 * Creates an empty pcap header suitable for peering.
	 * 
	 * @param type
	 *          memory allocation model type
	 */
	public PcapHeader(Type type) {
		super(STRUCT_NAME, type);
	}

	/**
	 * Gets the caplen field from the structure.
	 * 
	 * @return size of the capture packet data
	 */
	public int caplen() {
		return hdr_len();
	}

	/**
	 * Gets the hdr_len field from the structure.
	 * 
	 * @return value of the hdr_len field
	 */
	public native int hdr_len();

	/**
	 * Sets the hdr_len field.
	 * 
	 * @param len
	 *          new value for hdr_len field
	 */
	public native void hdr_len(int len);

	/**
	 * Gets the hdr_sec field value.
	 * 
	 * @return value of the hdr_sec field
	 */
	public native long hdr_sec();

	/**
	 * Sets the hdr_sec field.
	 * 
	 * @param ts
	 *          new value for hdr_sec field
	 */
	public native void hdr_sec(long ts);

	/**
	 * Gets the hdr_usec field.
	 * 
	 * @return value of the hdr_usec field
	 */
	public native int hdr_usec();

	/**
	 * Sets the hdr_usec field.
	 * 
	 * @param ts
	 *          new value for hdr_usec field
	 */
	public native void hdr_usec(int ts);

	/**
	 * Gets the hdr_wirelen field.
	 * 
	 * @return value of the hdr_wirelen field
	 */
	public native int hdr_wirelen();

	/**
	 * Sets the hdr_wirelen field.
	 * 
	 * @param len
	 *          new value for hdr_wirelen field
	 */
	public native void hdr_wirelen(int len);

	/**
	 * Converts hdr_usec field into nano seconds.
	 * 
	 * @return converted value of the hdr_usec field
	 */
	public long nanos() {
		return hdr_usec() * 1000;
	}

	/**
	 * Peers this header object with the supplied memory object.
	 * 
	 * @param memory
	 *          object to peer with this header
	 * @param offset
	 *          offset into memory object
	 * @return number of bytes peered
	 */
	public int peer(JBuffer memory, int offset) {
		return super.peer(memory, offset, sizeof());
	}

	/**
	 * Peers this header with the supplied buffer.
	 * 
	 * @param buffer
	 *          buffer to peer with
	 * @param offset
	 *          offset into the buffer
	 * @return number of bytes peered
	 */
	public int peerTo(JBuffer buffer, int offset) {
		return super.peer(buffer, offset, sizeof());
	}

	/**
	 * Peers this header to the user supplied header.
	 * 
	 * @param header
	 *          header to peer with
	 * @param offset
	 *          offset into the supplied header
	 * @return number of bytes peered
	 */
	public int peerTo(PcapHeader header, int offset) {
		return super.peer(header, offset, header.size());
	}

	/**
	 * Gets the hdr_sec field.
	 * 
	 * @return value of the hdr_sec field
	 */
	public long seconds() {
		return hdr_sec();
	}

	/**
	 * Converts the hdr_sec and hdr_usec fields into a java style absolute
	 * timestamp suitable for usage with java's <code>Date</code> object.
	 * 
	 * @return absolute capture timestamp in milli-seconds
	 */
	public long timestampInMillis() {
		long l = hdr_sec() * 1000 + hdr_usec() / 1000;

		return l;
	}

	/**
	 * Copies contents of this header to supplied buffer.
	 * 
	 * @param m
	 *          buffer to copy to
	 * @param offset
	 *          offset into the buffer
	 * @return number of bytes copied
	 */
	public int transferTo(JBuffer m, int offset) {
		return super.transferTo(m, 0, size(), offset);
	}

	/**
	 * Copies contents of this buffer into supplied byte array buffer.
	 * 
	 * @param m
	 *          buffer to copy to
	 * @param offset
	 *          offset into the buffer
	 * @return number of bytes copied
	 */
	public int transferTo(byte[] m, int offset) {
		return super.transferTo(m, 0, size(), offset);
	}

	/**
	 * Gets the value of hdr_wirelen field.
	 * 
	 * @return value of hdr_wirelen field
	 */
	public int wirelen() {
		return hdr_wirelen();
	}

	/**
	 * Unsupported operation.
	 * 
	 * @param caplen
	 *          ignored
	 */
	public void caplen(int caplen) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/**
	 * Unsupported operation.
	 * 
	 * @param nanos
	 *          ignored
	 */
	public void nanos(long nanos) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/**
	 * Unsupported operation.
	 * 
	 * @param seconds
	 *          ignored
	 */
	public void seconds(long seconds) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/**
	 * Unsupported operation.
	 * 
	 * @param wirelen
	 *          ignored
	 */
	public void wirelen(int wirelen) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/**
	 * Unsupported operation.
	 * 
	 * @param captureHeader
	 *          ignored
	 */
	public void initFrom(JCaptureHeader captureHeader) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/**
	 * Converts the hdr_sec and hdr_usec fields into a nano second absolute
	 * timestamp. The timestamp still maintains micro-second resolution.
	 * 
	 * @return absolute timestamp in nano seconds
	 */
	public long timestampInNanos() {
		return hdr_sec() * 1000000000 + hdr_usec() * 1000;
	}

	/**
	 * Converts the hdr_sec and hdr_usec fields into a micro second absolute
	 * timestamp.
	 * 
	 * @return absolute timestamp in micro seconds
	 */
	public long timestampInMicros() {
		return hdr_sec() * 1000000 + hdr_usec();
	}

}