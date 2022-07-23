/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.jnetpcap.examples;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;

/**
 * This example opens up a capture file found in jNetPcap's installation
 * directory for of the "source" distribution package and iterates over every
 * packet. The example also demonstrates how to property peer
 * <code>PcapHeader</code>, <code>JBuffer</code> and initialize a new
 * <code>PcapPacket</code> object which will contain a copy of the peered
 * packet and header data. The libpcap provide header and data are stored in
 * libpcap private memory buffer, which will be overriden with each iteration of
 * the loop. Therefore we use the constructor in <code>PcapPacket</code> to
 * allocate new memory to store header and packet buffer data and perform the
 * copy. The we
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class NextExExample {

	/**
	 * Start of our example.
	 * 
	 * @param args
	 *          ignored
	 */
	public static void main(String[] args) {
		final String FILE_NAME = "tests/test-l2tp.pcap";
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First - we open up the selected device
		 **************************************************************************/
		Pcap pcap = Pcap.openOffline(FILE_NAME, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening file for capture: "
			    + errbuf.toString());
			return;
		}

		/***************************************************************************
		 * Second - we create our main loop and our application We create some
		 * objects we will be using and reusing inside the loop
		 **************************************************************************/
		Ip4 ip = new Ip4();
		Ethernet eth = new Ethernet();
		PcapHeader hdr = new PcapHeader(JMemory.POINTER);
		JBuffer buf = new JBuffer(JMemory.POINTER);

		/***************************************************************************
		 * Third - we must map pcap's data-link-type to jNetPcap's protocol IDs.
		 * This is needed by the scanner so that it knows what the first header in
		 * the packet is.
		 **************************************************************************/
		int id = JRegistry.mapDLTToId(pcap.datalink());

		/***************************************************************************
		 * Fourth - we peer header and buffer (not copy, think of C pointers)
		 **************************************************************************/
		while (pcap.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {

			/*************************************************************************
			 * Fifth - we copy header and buffer data to new packet object
			 ************************************************************************/
			PcapPacket packet = new PcapPacket(hdr, buf);

			/*************************************************************************
			 * Six- we scan the new packet to discover what headers it contains
			 ************************************************************************/
			packet.scan(id);

			/*
			 * We use FormatUtils (found in org.jnetpcap.packet.format package), to
			 * convert our raw addresses to a human readable string.
			 */
			if (packet.hasHeader(eth)) {
				String str = FormatUtils.mac(eth.source());
				System.out.printf("#%d: eth.src=%s\n", packet.getFrameNumber(), str);
			}
			if (packet.hasHeader(ip)) {
				String str = FormatUtils.ip(ip.source());
				System.out.printf("#%d: ip.src=%s\n", packet.getFrameNumber(), str);
			}
		}

		/*************************************************************************
		 * Last thing to do is close the pcap handle
		 ************************************************************************/
		pcap.close();
	}
}
