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

import java.util.ArrayList;
import java.util.List;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>pcap_addr</code> structure. Holds pcap
 * addresses.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Library(preload = { PcapSockAddr.class

}, jni = Pcap.LIBRARY)
public final class PcapAddr {

	/**
	 * Inits the i ds.
	 */
	@LibraryInitializer
	private native static void initIDs();

	static {
		JNILibrary.register(PcapAddr.class);
	}

	/** The next. */
	private volatile PcapAddr next;

	/** The addr. */
	private volatile PcapSockAddr addr;

	/** The netmask. */
	private volatile PcapSockAddr netmask;

	/** The broadaddr. */
	private volatile PcapSockAddr broadaddr;

	/** The dstaddr. */
	private volatile PcapSockAddr dstaddr;

	/**
	 * Gets the next.
	 * 
	 * @return the next
	 */
	private final PcapAddr getNext() {
		return this.next;
	}

	/**
	 * pcap_addr.addr field.
	 * 
	 * @return the addr
	 */
	public final PcapSockAddr getAddr() {
		return this.addr;
	}

	/**
	 * pcap_addr.netmask field.
	 * 
	 * @return the netmask
	 */
	public final PcapSockAddr getNetmask() {
		return this.netmask;
	}

	/**
	 * pcap_addr.broadaddr field.
	 * 
	 * @return the broadaddr
	 */
	public final PcapSockAddr getBroadaddr() {
		return this.broadaddr;
	}

	/**
	 * pcap_addr.dstaddr field.
	 * 
	 * @return the dstaddr
	 */
	public final PcapSockAddr getDstaddr() {
		return this.dstaddr;
	}

	/**
	 * To list.
	 * 
	 * @return the list
	 */
	private List<PcapAddr> toList() {
		List<PcapAddr> list = new ArrayList<PcapAddr>();

		PcapAddr i = this;

		while (i != null) {
			list.add(i);

			i = i.next;
		}

		return list;
	}

	/**
	 * Debug information about this address object.
	 * 
	 * @return debug info
	 */
	@Override
	public String toString() {
		StringBuilder out = new StringBuilder();

		out.append("[");
		out.append("addr=").append(String.valueOf(addr));
		out.append(", mask=").append(String.valueOf(netmask));
		out.append(", broadcast=").append(String.valueOf(broadaddr));
		out.append(", dstaddr=").append(String.valueOf(dstaddr));
		out.append("]");

		return out.toString();
	}

}
