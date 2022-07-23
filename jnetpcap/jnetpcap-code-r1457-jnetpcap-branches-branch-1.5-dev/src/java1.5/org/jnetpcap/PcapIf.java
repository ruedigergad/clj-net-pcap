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

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>pcap_if_t</code> structure. Addresses is
 * replaced as a list to simulate a linked list of address structures. This is
 * not a JNI peering class, and is only a read-only object.
 * 
 * @author Sly Technologies, Inc.
 */
@Library(preload = {
		PcapIf.class,
		PcapAddr.class
}, jni = Pcap.LIBRARY)
public class PcapIf {

	/**
	 * Inits the i ds.
	 */
	@LibraryInitializer
	private native static void initIDs();

	static {
		JNILibrary.register(PcapIf.class);
	}

	/**
	 * The field is initialized to the next object in native linked list, but is
	 * not accessible from java.
	 */
	private volatile PcapIf next;

	/** The name. */
	private volatile String name;

	/** The description. */
	private volatile String description;

	/**
	 * Preallocate the list. The list will be filled in based on pcap_addr
	 * structure from JNI. The field can be assigned to any kind of list since JNI
	 * does dynamic lookup on the List.add method. We allocate a more efficient
	 * ArrayList with only 2 addresses max for its initial capacity, as its very
	 * rare to have interfaces assigned multiple addresses. The list will resize
	 * incase there are more then 2 automatically.
	 */
	private final List<PcapAddr> addresses = new ArrayList<PcapAddr>(2);

	/** The flags. */
	private volatile int flags;

	/**
	 * pcap_if.next field is unimportant since this java API fills in all the
	 * entries into a List. Since the field does exist, though we leave the method
	 * but make it private and not user accessible. This avoid when next is null
	 * issues.
	 * 
	 * @return the next
	 */
	private final PcapIf getNext() {
		return this.next;
	}

	/**
	 * pcap_if.name field.
	 * 
	 * @return the name
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * pcap_if.description field.
	 * 
	 * @return the description
	 */
	public final String getDescription() {
		return this.description;
	}

	/**
	 * A list of addresses for this field. The native C linked list of
	 * <code>pcap_if</code> structures is turned into a java <code>List</code> for
	 * convenience.
	 * 
	 * @return the addresses
	 */
	public final List<PcapAddr> getAddresses() {
		return this.addresses;
	}

	/**
	 * pcap_if.flags field.
	 * 
	 * @return the flags
	 */
	public final int getFlags() {
		return this.flags;
	}

	/**
	 * Retrieves the hardware address of this network interface. The native OS is
	 * queried via the appropriate OS calls to retrive the hardware address of the
	 * interface (MAC address). This is a direct call, not cached data.
	 * 
	 * @return hardware address as an array of bytes; this method returns null if
	 *         interface doesn't have or is incapable of having a hardware address
	 *         such as loopback interfaces and others
	 * @throws IOException
	 *           if there was a problem retrieving the address
	 */
	public byte[] getHardwareAddress() throws IOException {
		return PcapUtils.getHardwareAddress(this);
	}

	/**
	 * Debug string.
	 * 
	 * @return debug string
	 */
	@Override
	public String toString() {
		StringBuilder out = new StringBuilder();

		out.append("<");
		if (addresses != null && addresses.isEmpty() == false) {
			out.append("flags=").append(flags);
			out.append(", addresses=").append(addresses);
			out.append(", ");
		}
		out.append("name=").append(name);
		out.append(", desc=").append(description);

		out.append(">");

		// if (next != null) {
		// out.append("\n").append(next.toString());
		// }

		return out.toString();
	}

	/**
	 * @return
	 */
	public static PcapIf findDefaultIf(StringBuilder errbuf) {
		List<PcapIf> alldevs = new LinkedList<PcapIf>();
		if (errbuf == null) {
			errbuf = new StringBuilder();
		}
		if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
			return null;
		}

		for (PcapIf dev : alldevs) {
			List<PcapAddr> addrs = dev.getAddresses();
			if (addrs.isEmpty()) {
				continue;
			}
			return dev;
		}

		return null;
	}

	/**
	 * @param object
	 * @return
	 */
	public static List<PcapIf> findAllDevs(StringBuilder errbuf) {
		List<PcapIf> alldevs = new LinkedList<PcapIf>();
		if (errbuf == null) {
			errbuf = new StringBuilder();
		}
		Pcap.findAllDevs(alldevs, errbuf);
		return alldevs;
	}
}
