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
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.TestUtils;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class TestExamples
    extends
    TestCase {

	private final static String FILE = "C:\\Documents and Settings\\markbe.DESKTOP-HP.000\\My Documents\\tmp\\tmp-capture-file.cap";

	/**
	 * @throws java.lang.Exception
	 */

	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */

	public void tearDown() throws Exception {
	}

	/**
	 * Mimic of the popular Class-Example but with offline file instead of live
	 * network interface.
	 */
	public void testClassisExampleOffline() {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		assertFalse(errbuf.toString(), r == Pcap.NOT_OK || alldevs.isEmpty());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
		Pcap pcap = Pcap.openOffline(FILE, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		/***************************************************************************
		 * Third we create a packet hander which will be dispatched to from the
		 * libpcap loop.
		 **************************************************************************/
		PcapHandler<String> printSummaryHandler = new PcapHandler<String>() {

			public void nextPacket(
			    String user,
			    long seconds,
			    int useconds,
			    int caplen,
			    int len,
			    ByteBuffer buffer) {
				
				assertTrue(seconds > 0);
				assertTrue(useconds > 0);
				assertTrue(caplen > 0);
				assertTrue(len > 0);
			}
		};

		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets
		 **************************************************************************/
		assertTrue(pcap.loop(10, printSummaryHandler, "jNetPcap rocks!") == Pcap.OK);

		/*
		 * Last thing to do is close the pcap handle
		 */
		pcap.close();

	}

	public void testPcapUmpderExampleOffline() {
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		Pcap pcap = Pcap.openOffline(FILE, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		/***************************************************************************
		 * Thirds we create a PcapDumper and associate it with the pcap capture
		 **************************************************************************/
		String ofile = "tmp-capture-file.cap";
		PcapDumper dumper = pcap.dumpOpen(ofile); // output file

		/***************************************************************************
		 * Fouth we create a packet hander which receive packets and tell the dumper
		 * to write those packets to its output file
		 **************************************************************************/
		PcapHandler<PcapDumper> dumpHandler = new PcapHandler<PcapDumper>() {

			public void nextPacket(
			    PcapDumper dumper,
			    long seconds,
			    int useconds,
			    int caplen,
			    int len,
			    ByteBuffer buffer) {

				dumper.dump(seconds, useconds, caplen, len, buffer);
			}
		};

		/***************************************************************************
		 * Fifth we enter the loop and tell it to capture 10 packets. We pass in the
		 * dumper created in step 3
		 **************************************************************************/
		assertTrue(pcap.loop(Pcap.LOOP_INFINATE, dumpHandler, dumper) == Pcap.OK);

		File file = new File(ofile);

		assertTrue(file.exists());
		assertEquals(FILE, new File(FILE).length(), file.length());

		/*
		 * Last thing to do is close the dumper and pcap handles
		 */
		dumper.close(); // Won't be able to delete without explicit close
		pcap.close();

		/* Clean up */
		file.delete(); // Cleanup
		assertFalse(file.exists());

	}
}
