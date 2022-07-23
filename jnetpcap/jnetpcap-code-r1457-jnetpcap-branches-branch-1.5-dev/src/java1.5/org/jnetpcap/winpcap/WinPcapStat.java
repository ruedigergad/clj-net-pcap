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
package org.jnetpcap.winpcap;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapStat;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>pcap_stat</code> structure providing all
 * available extensions part of WinPcap extensions. Provides access to
 * additional statical fields as returned from a call to WinPcap.statsEx().
 * 
 * @see WinPcap#statsEx()
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Library(jni = Pcap.LIBRARY)
public class WinPcapStat extends PcapStat {

	/**
	 * Inits the i ds.
	 */
	@LibraryInitializer
	private native static void initIDs();

	static {
		JNILibrary.register(WinPcapSamp.class);
	}

	/**
	 * Empty stats structure that will be filled in after the call to
	 * <code>statsEx</code>.
	 */
	private WinPcapStat() {

	}

	/**
	 * number of packets that are received by the application.
	 * 
	 * @return the capt
	 */
	public long getCapt() {
		return super.capt;
	}

	/**
	 * number of packets lost on the network.
	 * 
	 * @return the netdrop
	 */
	public long getNetdrop() {
		return super.netdrop;
	}

	/**
	 * number of packets sent by the server on the network.
	 * 
	 * @return the sent
	 */
	public long getSent() {
		return super.sent;
	}

	/**
	 * Dumps all the values as a string.
	 * 
	 * @return the string
	 */
	@Override
	public String toString() {

		out.setLength(0);

		out.append("recv=").append(getRecv());
		out.append(", drop=").append(getDrop());
		out.append(", ifdrop=").append(getIfDrop());
		out.append(", capt=").append(getCapt());
		out.append(", netdrop=").append(getNetdrop());
		out.append(", sent=").append(getSent());

		return out.toString();
	}
}
