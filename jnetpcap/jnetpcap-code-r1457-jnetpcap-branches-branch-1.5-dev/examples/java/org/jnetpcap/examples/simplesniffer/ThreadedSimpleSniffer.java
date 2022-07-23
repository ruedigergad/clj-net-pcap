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
import java.util.Timer;
import java.util.TimerTask;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDLT;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;
import org.jnetpcap.winpcap.WinPcap;

/**
 * Threaded Simple Sniffer example. Where pcap is started in an infinate
 * dispatch loop. Packets are delivered to a handler that keeps track of how
 * much data has arrived and every second, with the help of a IntRate class,
 * prints out various rate usage statistics. The statistics diplayer is in a
 * different thread, that wakes up every second and dipsplays any statistics if
 * they are ready. The difference between this and the simpler sniffer is that
 * the threaded is guarranteed to wake up every second, while the non-threaded
 * cusin is at a mercy of a packet arriving, before it can display statistics.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class ThreadedSimpleSniffer {
	private static final StringBuilder errbuf = new StringBuilder();

	private WinPcap pcap = null;

	private static final IntRate bitRate = new IntRate("bits", "b", 1024);

	private static final IntRate packetRate = new IntRate("packets", "p", 1000);

	private Timer timer;

	public static void main(String[] args) {

		if (WinPcap.isSupported() == false) {
			System.out.println("WinPcap extensions not supported on this platform.");
			return;
		}

		ThreadedSimpleSniffer sniffer = new ThreadedSimpleSniffer();

		sniffer.openFirstFound(PcapDLT.EN10MB);

		sniffer.startDisplayThread();

		sniffer.run();
		try {
			sniffer.waitForDisplayThread();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		sniffer.close();
	}

	/**
	 * 
	 */
	private void run() {

		if (pcap == null) {
			throw new IllegalStateException("Pcap not opened.");
		}

		PcapHandler<?> h = new PcapHandler<Object>() {
			/*
			 * (non-Javadoc)
			 * 
			 * @see org.jnetpcap.PcapHandler#nextPacket(java.lang.Object, long, int,
			 *      int, int, java.nio.ByteBuffer)
			 */
			public void nextPacket(Object userObject, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

				// System.out.printf(
				// "Received packet caplen=%-4d len=%-4d counter=%-6d\n", caplen, len,
				// byteCounter.get());

				bitRate.delta(len * 8); // in bits
				packetRate.delta(1);
			}
		};

		System.out.println("Started dispatcher");
		pcap.loop(-1, h, null);
		pcap = null;
		System.out.println("Dispatcher stopped.");
	}

	public void waitForDisplayThread() throws InterruptedException {
		timer.wait();
	}

	private void startDisplayThread() {
		final int DELTA = 1000;
		timer = new Timer();
		TimerTask task = new TimerTask() {

			@Override
			public void run() {
				if (bitRate.isEmpty() || packetRate.isEmpty()) {
					return; // Nothing to print
				}

				System.out.printf("%s :: %s\n", bitRate.toString(), packetRate
				    .toString());

				bitRate.reset();
				packetRate.reset();
			}

		};

		timer.scheduleAtFixedRate(task, 0, DELTA);
	}

	public void openFirstFound(PcapDLT dlt) {

		List<PcapIf> ifs = new ArrayList<PcapIf>();
		if (Pcap.findAllDevs(ifs, errbuf) != 0) {
			System.err.println("No interfaces found of specified type :" + dlt);
			return;
		}

		System.out.println(ifs.toString());

		for (PcapIf i : ifs) {
			if ((pcap = WinPcap.openLive(i.getName(), 2 * 1024, 1, 0, errbuf)) == null) {
				System.err.printf("Capture open %s: %s\n", i.getName(), errbuf
				    .toString());
			}

			if (pcap.datalink() == dlt.value) {
				System.out.printf("Opened interface\n\t%s\n\t%s\n", i.getName(), i
				    .getDescription());
				break;
			} else {
				pcap = null;
			}
		}

		if (pcap == null) {
			System.err.printf("Unable to find interface with dlt of %s\n", dlt);
			return;
		}

		/*
		 * Alternative way is to use WinPcap.open() and use flag:
		 * WinPcap.OPENFLAG_MAX_RESPONSIVENESS. Flag not supported with openLive.
		 */
		pcap.setMinToCopy(0); // Make the capture realtime, no waits

	}

	public void close() {
		if (pcap == null) {
			return;
		}

		pcap.close();
		pcap = null;
	}
}
