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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;

/**
 * This example is uses pcap library to capture live packets and dump them to a
 * set of files. Packets are captured for a certain amount of time and dumped to
 * a file. After the time interval expires a new capture files is created and
 * next set of packets is dumped for that same time interval and so on.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapDumperExampleMultipleFiles {

	public static final String DATE_FORMAT_NOW = "yyyyMMddHHmmss";
	public static final int CAPTURE_INTERVAL = 10 * 1000; // 10 seconds in
															// millis

	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
		// NICs
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
		PcapIf device = alldevs.get(0); // We know we have at least 1 device

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no truncation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = CAPTURE_INTERVAL; // No timeout, non-interactive traffic
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout,
				errbuf);
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
					+ errbuf.toString());
			return;
		}

		/***************************************************************************
		 * Thirds we create a main loop which will loop over all capture intervals
		 * and create the necessary dumper for each loop
		 **************************************************************************/

		try {
			while (true) {

				String ofile = "c:\\temp\\pcap" + now().toString() + ".pcap";
				final PcapDumper dumper = pcap.dumpOpen(ofile);
				final long interval = System.currentTimeMillis() + CAPTURE_INTERVAL;
				
				System.out.printf("new dump files = %s\n", ofile);

				/***************************************************************************
				 * Fourth we create a packet hander which receive packets and
				 * tell the dumper to write those packets to its output file
				 **************************************************************************/
				JBufferHandler<Pcap> dumpHandler = new JBufferHandler<Pcap>() {

					public void nextPacket(PcapHeader header, JBuffer buffer,
							Pcap pcap) {
						
						dumper.dump(header, buffer);
						
						if (System.currentTimeMillis() > interval) {
							pcap.breakloop();
						}

					}
				};

				/***************************************************************************
				 * Fifth we enter the loop and tell it to capture 10 packets. We
				 * pass in the dumper created in step 3
				 **************************************************************************/
				pcap.loop(Pcap.LOOP_INFINATE, dumpHandler, pcap);

				dumper.close(); // close out the dumper and flush any unwritten packets
			}
		} finally {

			/*
			 * Last thing to do is close the dumper and pcap handles
			 */
			pcap.close();
		}

	}

	public static String now() {
		Calendar cal = Calendar.getInstance();
		SimpleDateFormat df = new SimpleDateFormat(DATE_FORMAT_NOW);
		return df.format(cal.getTime());
	}

}
