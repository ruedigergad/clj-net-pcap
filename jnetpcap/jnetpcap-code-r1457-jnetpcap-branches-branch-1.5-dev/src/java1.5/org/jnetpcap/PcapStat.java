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

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>pcap_stat</code> structure providing only the
 * core statistics. Class that is filled in by a call to method
 * <code>Pcap.stats</code>. The structure keeps statisical values on an
 * interface.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Library(preload = { Pcap.class
}, jni = Pcap.LIBRARY)
public class PcapStat {

	/**
	 * Inits the i ds.
	 */
	@LibraryInitializer
	private static native void initIDs();

	static {
		JNILibrary.register(PcapStat.class);
	}

	/**
	 * For toString() to build its string. Should be made thread local.
	 */
	protected final static StringBuilder out = new StringBuilder();

	/** number of packets received. */
	private long recv;

	/** number of packets dropped. */
	private long drop;

	/** drops by interface XXX not yet supported. */
	private long ifDrop;

	/*
	 * The rest of the fields are only filled in by a call to WinPcap.statsEx
	 * which returns a subclass of PcapStat called WinPcapStat. The fields are
	 * only accessible from WinPcapStat class.
	 */

	/** number of packets that are received by the application. */
	protected long capt;

	/** number of packets sent by the server on the network. */
	protected long sent;

	/** number of packets lost on the network. */
	protected long netdrop;

	/**
	 * Number of packets transmitted on the network
	 * 
	 * @return the recv
	 */
	public final long getRecv() {
		return this.recv;
	}

	/**
	 * number of packets dropped by the driver
	 * 
	 * @return the drop
	 */
	public final long getDrop() {
		return this.drop;
	}

	/**
	 * drops by interface. Not supported.
	 * 
	 * @return the ifdrop
	 */
	public final long getIfDrop() {
		return this.ifDrop;
	}

	/**
	 * Debug string return debug string.
	 * 
	 * @return the string
	 */
	@Override
	public String toString() {
		out.setLength(0);

		out.append("recv=").append(recv);
		out.append(", drop=").append(drop);
		out.append(", ifdrop=").append(ifDrop);

		return out.toString();
	}
}
