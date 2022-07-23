/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.examples.packet;

import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.vpn.L2TP;

/**
 * This example is demonstrates how to work with packets after they have been
 * captured.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class WorkingWithPacketsExample {

	public static void main(String[] args) {

		final String fname = TestUtils.L2TP; // "tests/test-l2tp.pcap"

		Pcap pcap = openFile(TestUtils.L2TP);
		if (pcap == null) {
			System.exit(1);
		}

		/*
		 * Here are some of the protocol headers we will be working with. Only one
		 * instance of each is neccessary, since all heades are reused very
		 * efficiently.
		 */

		Ip4 ip4 = new Ip4();
		Ip6 ip6 = new Ip6();
		Ethernet eth = new Ethernet();
		L2TP l2tp = new L2TP();

		Map<Integer, PcapPacket> map = new HashMap<Integer, PcapPacket>();

		/*
		 * We create an empty packet, that will be peered by nextEx method with each
		 * packet returned from libpcap library. The peered packet points at the
		 * libpcap controlled memory. This is OK, no data copies, if we can
		 * immediately do something with the data and not need the contents, which
		 * will change, by next iteration of the main loop. Otherwise we need to
		 * make a copy into our memory space. The easiest way to make the copy is to
		 * use a PcapPacket constructor which will perform the copy and create a new
		 * packet object, that we can keep all in one step.
		 */
		PcapPacket packet = new PcapPacket(JMemory.POINTER);
		while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {

			int hash = 0;

			/*
			 * Check if the packet has ethernet header
			 */
			if (packet.hasHeader(eth)) {
				byte[] src = eth.source();

				hash = 0;
				hash = src[0] + src[1] + src[2] + src[3] + src[4] + src[5];

				System.out.printf("Found ethernet header src=%s\n", FormatUtils
				    .mac(src));
			}

			/*
			 * Check if the packet has Ip4 header and the header has correct
			 * checksum. Notice we can use ip4 instances immediately after hasHeader.
			 * The boolean condition is evaluated from left to right and if the left
			 * part failed because there was no ip4 header in the packet, the
			 * right side would never get executed.
			 */
			if (packet.hasHeader(ip4) && ip4.isChecksumValid()) {
				byte[] src = ip4.source();

				hash = 0;
				hash = src[0] + src[1] + src[2] + src[3];

				System.out.printf("Found ip4 header src=%s\n", FormatUtils
				    .ip(src));

			}

			/*
			 * Check if the packet has Ip6 header
			 */
			if (packet.hasHeader(ip6)) {
				byte[] src = ip4.source();

				hash = 0;
				for (byte b: src) {
					hash += b;
				}

				System.out.printf("Found ip6 header src=%s\n", FormatUtils
				    .ip(src));

			}

			/*
			 * Check if the packet has l2tp header. If we find a L2TP header we copy
			 * the packet to a new packet object that we can store on an array or
			 * collection.
			 */
			if (packet.hasHeader(l2tp)) {
				PcapPacket copy = new PcapPacket(packet);

				map.put(hash, copy); // Store our copy. Its safe to store long term
			}

		}
		
		/*
		 * Don't forget the close the pcap handle
		 */
		pcap.close();

	}

	public static Pcap openFile(String fname) {
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		Pcap pcap = Pcap.openOffline(fname, errbuf);

		return pcap;
	}
}
