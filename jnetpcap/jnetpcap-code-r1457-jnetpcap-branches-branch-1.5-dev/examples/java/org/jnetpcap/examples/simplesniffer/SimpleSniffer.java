/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.examples.simplesniffer;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDLT;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;

/**
 * Simple Sniffer example. Where pcap is started in an infinate dispatch loop.
 * Packets are delivered to a handler that keeps track of how much data has
 * arrived and every second, with the help of a IntRate class, prints out
 * various rate usage statistics.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class SimpleSniffer {
	private static final StringBuilder errbuf = new StringBuilder();

	private Pcap pcap = null;

	private static final IntRate bitRate = new IntRate("bits", "b", 1024);

	private static final IntRate packetRate = new IntRate("packets", "p", 1000);

	public static void main(String[] args) {

		SimpleSniffer sniffer = new SimpleSniffer();

		sniffer.openFirstFound(PcapDLT.EN10MB);

		sniffer.loop();

		sniffer.close();
	}

	/**
	 * 
	 */
	private void loop() {

		if (pcap == null) {
			throw new IllegalStateException("Pcap not opened.");
		}

		final PcapHandler<?> h = new PcapHandler<Object>() {

			private long tstamp = 0;

			/*
			 * (non-Javadoc)
			 * 
			 * @see org.jnetpcap.PcapHandler#nextPacket(java.lang.Object, long, int,
			 *      int, int, java.nio.ByteBuffer)
			 */
			public void nextPacket(Object userObject, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

				bitRate.delta(len * 8); // in bits
				packetRate.delta(1);

				// Only display stats every 1 second (1000ms)
				long d = System.currentTimeMillis() - tstamp;

				if (d < 1000) {
					return;
				}
				tstamp = System.currentTimeMillis();

				System.out.printf("caplen=%d len=%d\n", caplen, len);

				if (bitRate.isEmpty() || packetRate.isEmpty()) {
					return; // Nothing to print
				}

				System.out.printf("%s :: %s\n", bitRate.toString(), packetRate
				    .toString());

				bitRate.reset();
				packetRate.reset();
			}
		};

		System.out.println("Started dispatcher");
		pcap.loop(Pcap.LOOP_INFINATE, h, null);

		pcap.close();
		pcap = null;
		System.out.println("Dispatcher stopped.");
	}

	public void openFirstFound(PcapDLT dlt) {

//		pcap = Pcap.openLive(
//		    "\\Device\\NPF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D}", 32, 0, 60000,
//		    errbuf);
		
		List<PcapIf> ifs = new ArrayList<PcapIf>();
		if (Pcap.findAllDevs(ifs, errbuf) != 0) {
			System.err.println("No interfaces found of specified type :" + dlt);
			return;
		}

		System.out.println(ifs.toString());

		for (PcapIf i : ifs) {
			errbuf.setLength(0);
			if ((pcap = Pcap.openLive(i.getName(), 64, Pcap.MODE_NON_PROMISCUOUS,
			    1000, errbuf)) == null) {
				System.err.printf("Capture open %s: %s\n", i.getName(), errbuf
				    .toString());
			}

			if (pcap.datalink() == dlt.value) {
				System.out.printf("Opened interface\n\t%s\n\t%s\n", i.getName(), i
				    .getDescription());
				System.out.printf("Warnings='%s'\n", errbuf.toString());
				break;
			} else {
				pcap.close();
				pcap = null;
			}
		}

		if (pcap == null) {
			System.err.printf("Unable to find interface with dlt of %s\n", dlt);
			return;
		}

		// Now apply a no-op filter so that snaplen will work
		PcapBpfProgram prg = new PcapBpfProgram();
		if (pcap.compile(prg, "len < 65535", 0, 0) == Pcap.NOT_OK) {
			System.err.println("Error while setting filter: " + pcap.getErr());
			return;
		}
		pcap.setFilter(prg);
		System.out.println("Filter set OK");

	}

	public void close() {
		if (pcap == null) {
			return;
		}

		pcap.close();
		pcap = null;
	}
}
