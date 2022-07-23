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

import java.io.File;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDLT;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.format.FormatUtils;

/**
 * This example demonstrates how to open up a pcap dumper capable of writing
 * packets to a capture file in pcap file format, using a dummy pcap object that
 * is only suitable for creating our PcapDumper. Since the Pcap capture object
 * is a dummy, one that does not capture anything, we have to supply the packet
 * objects we want to write to the file our selves.
 * <p>
 * This example first creates an in memory packet and an in memory PcapHeader
 * that we can pass to our dumper. The dumper simply writes out the packet to
 * the output file it was opened for.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapDumperExampleUsingOpenDead {

	/**
	 * Our main entry point into this example.
	 * 
	 * @param args
	 *          all arguments are ignored and none are expected
	 */
	public static void main(String[] args) {

		/***************************************************************************
		 * First create an in memory packet we will write to dumper 10 times. This
		 * particular packet is a L2TP packet with Ethernet/Ip4/Udp/L2TP headers in
		 * it.
		 **************************************************************************/
		final JBuffer packet =
		    new JBuffer(FormatUtils.toByteArray(""
		        + "0007e914 78a20010 7b812445 080045c0"
		        + "00280005 0000ff11 70e7c0a8 62dec0a8"
		        + "65e906a5 06a50014 e04ac802 000c0002"
		        + "00000002 00060000 00000000"));
		final PcapHeader header = new PcapHeader(packet.size(), packet.size());

		/***************************************************************************
		 * Second we open up a dummy pcap session. Pcap.openDead creates a dummy
		 * pcap_t structure which does not perform any capturing of packets, but is
		 * perfect for creating other pcap dependent objects such as PcapDumper or
		 * PcapBpfFilter. Note that using a Pcap.loop, Pcap.dispatch or any other
		 * methods with the "dead" pcap object is illegal.
		 **************************************************************************/
		final int dlt = PcapDLT.EN10MB.value;
		final int snaplen = 64 * 1024;

		final Pcap pcap = Pcap.openDead(dlt, snaplen);

		/*
		 * An error can only occur if the parameters to openDead are drastically
		 * invalid. Otherwise this method never returns null.
		 */
		if (pcap == null) {
			System.err.printf("Error while dummy capture: " + pcap.getErr());
			return;
		}

		/***************************************************************************
		 * Third we create a PcapDumper and associate it with a dead pcap capture.
		 **************************************************************************/
		final String ofile = "tmp-capture-file.pcap";

		final PcapDumper dumper = pcap.dumpOpen(ofile);

		/***************************************************************************
		 * Fouth we create loop that writes the packet out to a file multiple times.
		 **************************************************************************/
		final int COUNT = 10; // write 10 packets

		for (int i = 0; i < COUNT; i++) {
			dumper.dump(header, packet);
		}

		final File file = new File(ofile);
		System.out.printf("%s file has %d bytes in it!\n", ofile, file.length());

		/***************************************************************************
		 * Last thing to do is close the dumper and pcap handles
		 **************************************************************************/
		dumper.close(); // Won't be able to delete without explicit close
		pcap.close();

		if (file.exists()) {
			 file.delete(); // Cleanup
		}

	}
}
