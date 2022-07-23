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

import org.jnetpcap.packet.format.FormatUtils;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>struct sockaddr</code> structure. The class
 * contains the same fields of the counter part C structure. In jNetPcap library
 * its fields are initialized within the native library and returned to java
 * space. The class is readonly, and only provides getter methods.
 * 
 * @author Sly Technologies, Inc.
 */
@Library(preload = { Pcap.class
}, jni = Pcap.LIBRARY)
public class PcapSockAddr {

	/**
	 * Inits the i ds.
	 */
	@LibraryInitializer
	private native static void initIDs();

	static {
		JNILibrary.register(PcapSockAddr.class);
	}

	/** Socket family internet version 4. */
	public final static int AF_INET = 2;

	/** Socket family internet version 6. */
	public final static int AF_INET6 = 23;

	/** The family. */
	private volatile short family;

	/** The data. */
	private volatile byte[] data;

	/**
	 * Gets the socket's protocol family identifier.
	 * 
	 * @return the family
	 */
	public final short getFamily() {
		return this.family;
	}

	/**
	 * Gets protocol family specifiy array of bytes which contain the protocol's
	 * address. Length of the byte[] is protocol type dependent.
	 * 
	 * @return the data
	 */
	public final byte[] getData() {
		return this.data;
	}

	/**
	 * U.
	 * 
	 * @param b
	 *          the b
	 * @return the int
	 */
	private int u(byte b) {
		return (b >= 0) ? b : b + 256;
	}

	/**
	 * Debug string.
	 * 
	 * @return debug string
	 */
	@Override
	public String toString() {
		/*
		 * Fixed bug#128 - PcapSockAddr.toString() should use standard IPv6
		 */
		switch (family) {
		case AF_INET:
			return "[INET4:" + FormatUtils.ip(data) + "]";

		case AF_INET6:
			return "[INET6:" + FormatUtils.ip(data) + "]";

		default:
			return "[" + family + "]";
		}

	}
}
