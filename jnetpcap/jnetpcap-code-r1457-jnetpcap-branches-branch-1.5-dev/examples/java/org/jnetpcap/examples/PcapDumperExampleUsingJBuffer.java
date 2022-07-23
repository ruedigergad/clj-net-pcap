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

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;

/**
 * This example is the classic libpcap example shown in nearly every tutorial on
 * libpcap. It gets a list of network devices, presents a simple ASCII based
 * menu and waits for user to select one of those interfaces. We will just
 * select the first interface in the list instead of taking input to shorten the
 * example. Then it opens that interface for live capture. Using a packet
 * handler it goes into a loop to catch a few packets, say 10. Prints some
 * simple info about the packets, and then closes the pcap handle and exits.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class PcapDumperExampleUsingJBuffer {

	@SuppressWarnings("deprecation")
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
		 * Thirds we create a PcapDumper and associate it with the pcap capture
		 **************************************************************************/
		String ofile = "tmp-capture-file.cap";
		PcapDumper dumper = pcap.dumpOpen(ofile); // output file

		/***************************************************************************
		 * Fouth we create a packet hander which receive packets and tell the dumper
		 * to write those packets to its output file
		 **************************************************************************/
		JBufferHandler<PcapDumper> dumpHandler = new JBufferHandler<PcapDumper>() {

			public void nextPacket(PcapHeader header, JBuffer buffer,
			    PcapDumper dumper) {

				dumper.dump(header, buffer);
			}
		};

		/***************************************************************************
		 * Fifth we enter the loop and tell it to capture 10 packets. We pass in the
		 * dumper created in step 3
		 **************************************************************************/
		pcap.loop(10, dumpHandler, dumper);

		File file = new File(ofile);
		System.out.printf("%s file has %d bytes in it!\n", ofile, file.length());

		/*
		 * Last thing to do is close the dumper and pcap handles
		 */
		dumper.close(); // Won't be able to delete without explicit close
		pcap.close();

		if (file.exists()) {
			file.delete(); // Cleanup
		}

	}
}
