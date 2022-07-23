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
package org.jnetpcap.examples;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.winpcap.WinPcap;
import org.jnetpcap.winpcap.WinPcapSendQueue;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class WinPcapSendQueueTransmitExampleUsingPcapHeader {

	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}
		PcapIf device = alldevs.get(0); // We know we have atleast 1 device

		/***************************************************************************
		 * Second we open a network interface
		 **************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		WinPcap pcap = WinPcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		/***************************************************************************
		 * Third we create our crude packet queue we will transmit out 
		 * This creates a small queue full of broadcast packets
		 **************************************************************************/
		WinPcapSendQueue queue = WinPcap.sendQueueAlloc(512);
		PcapHeader hdr = new PcapHeader(128, 128);
		byte[] pkt = new byte[128];
		
		Arrays.fill(pkt, (byte) 255); // Broadcast
		queue.queue(hdr, pkt); // Packet #1
		queue.queue(hdr, pkt); // Packet #2

		Arrays.fill(pkt, (byte) 0x11); // Junk packet
		queue.queue(hdr, pkt); // Packet #3

		/***************************************************************************
		 * Fourth We send our packet off using open device
		 **************************************************************************/
		r = pcap.sendQueueTransmit(queue, WinPcap.TRANSMIT_SYNCH_ASAP);
		if (r != queue.getLen()) {
			System.err.println(pcap.getErr());
			return;
		}


		/***************************************************************************
		 * Lastly we close
		 **************************************************************************/
		pcap.close();

	}

}
