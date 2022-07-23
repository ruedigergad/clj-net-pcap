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

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>pcap_pkthdr</code> structure. This classes
 * fields are initialized with values from the C structure. There are no setter
 * methods, since the <code>pcap_pkthdr</code> C structure is used in
 * read-only fassion.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @deprecated replaced by PcapHeader
 * @see PcapHeader
 */
public class PcapPktHdr {

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs();

	static {
		initIDs();
	}

	/** The seconds. */
	private volatile long seconds;

	/** The useconds. */
	private volatile int useconds;

	/** The caplen. */
	private volatile int caplen;

	/** The len. */
	private volatile int len;

	/**
	 * Initializes the timestamp fields to current time and length fields to 0.
	 */
	public PcapPktHdr() {
		this.seconds = System.currentTimeMillis() / 1000; // In seconds
		this.useconds = (int) (System.nanoTime() / 1000); // Microseconds

		this.caplen = 0;
		this.len = 0;
	}

	/**
	 * Allocates a new packet header and initializes the caplen and len fields.
	 * The timestamp fields are initialized to current timestamp.
	 * 
	 * @param caplen
	 *          amount of data captured
	 * @param len
	 *          original packet length
	 */
	public PcapPktHdr(int caplen, int len) {
		this.caplen = caplen;
		this.len = len;

		this.seconds = System.currentTimeMillis() / 1000; // In seconds
		this.useconds = (int) (System.nanoTime() / 1000); // Microseconds
	}

	/**
	 * Instantiates a new pcap pkt hdr.
	 * 
	 * @param seconds
	 *          time stamp in seconds
	 * @param useconds
	 *          a fraction of a second. Valid value is from 0 to 999,999.
	 * @param caplen
	 *          amount of data captured
	 * @param len
	 *          original packet length
	 */
	public PcapPktHdr(long seconds, int useconds, int caplen, int len) {
		this.seconds = seconds;
		this.useconds = useconds;
		this.caplen = caplen;
		this.len = len;
	}

	/**
	 * Capture timestamp in seconds.
	 * 
	 * @return the seconds
	 */
	public final long getSeconds() {
		return this.seconds;
	}

	/**
	 * Capture timestamp in microseconds fraction.
	 * 
	 * @return the useconds
	 */
	public final int getUseconds() {
		return this.useconds;
	}

	/**
	 * Number of bytes actually captured.
	 * 
	 * @return the caplen
	 */
	public final int getCaplen() {
		return this.caplen;
	}

	/**
	 * Number of original bytes in the packet.
	 * 
	 * @return the len
	 */
	public final int getLen() {
		return this.len;
	}

	/**
	 * Sets the seconds.
	 * 
	 * @param seconds
	 *          the seconds to set
	 */
	public final void setSeconds(long seconds) {
		this.seconds = seconds;
	}

	/**
	 * Sets the useconds.
	 * 
	 * @param useconds
	 *          the useconds to set
	 */
	public final void setUseconds(int useconds) {
		this.useconds = useconds;
	}

	/**
	 * Sets the caplen.
	 * 
	 * @param caplen
	 *          the caplen to set
	 */
	public final void setCaplen(int caplen) {
		this.caplen = caplen;
	}

	/**
	 * Sets the len.
	 * 
	 * @param len
	 *          the len to set
	 */
	public final void setLen(int len) {
		this.len = len;
	}

}
