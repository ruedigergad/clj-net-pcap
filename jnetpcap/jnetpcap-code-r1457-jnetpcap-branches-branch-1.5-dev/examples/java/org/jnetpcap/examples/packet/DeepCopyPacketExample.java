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

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * 
 * @author Sly Technologies, Inc.
 */
public class DeepCopyPacketExample {

	/**
	 * @param args
	 */
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

		System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), device
			    .getDescription());
		}

		PcapIf device = alldevs.get(0); // We know we have atleast 1 device
		System.out.printf("\nChoosing '%s' on your behalf:\n", device
		    .getDescription());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		Pcap pcap =
		    Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}

		/***************************************************************************
		 * Third setup a queue and a packet handler
		 **************************************************************************/
		Queue<PcapPacket> queue = new ArrayBlockingQueue<PcapPacket>(20);
		PcapPacketHandler<Queue<PcapPacket>> handler =
		    new PcapPacketHandler<Queue<PcapPacket>>() {

			    public void nextPacket(PcapPacket temporary, Queue<PcapPacket> queue) {
				    PcapPacket permanent = new PcapPacket(temporary); // Deep copy

				    queue.offer(permanent);
			    }
		    };

		if (pcap.loop(10, handler, queue) != Pcap.OK) {
			System.err.println(pcap.getErr());

		} else if (queue.size() != 10) {
			System.err.println("expected 10 packets in the queue");

		} else {
			System.out.println("Success we have 10 packets in the queue, "
			    + "here is the first one");
			System.out.println(queue.poll().toString());
		}

		pcap.close();
	}
}
