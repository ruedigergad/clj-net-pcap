/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.TestUtils;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestLivePerformance
    extends
    TestUtils {

	long ts = 0;

	long te = 0;

	long pkt = 0;

	long bytes = 0;

	long drops = 0;

	long totPkt = 0;

	long totBytes = 0;
	
	long totTs = 0;

	long totTe = 0;

	public void startStats() {

		if (ts == 0) {
			totTs = System.currentTimeMillis();
		}
		ts = System.currentTimeMillis();
		te = ts;
		pkt = 0;
		bytes = 0;
	}

	public void endStats() {
		te = System.currentTimeMillis();
		totTe = te;

		totPkt += pkt;
		totBytes += bytes;
	}

	public void printStats(Pcap pcap) {
		PcapStat stats = new PcapStat();

		pcap.stats(stats);

		double pps = ((double) pkt / ((double) (te - ts) / 1000.));
		double bps = ((double) (bytes * 8) / ((double) (te - ts) / 1000.));

		System.out.printf(
		    "recv=%d, drop=%d, ifDrop=%d pps=%.2f bps=%.2fKb ave=%d bytes\n",
		    stats.getRecv(), stats.getDrop(), stats.getIfDrop(), pps, bps / 1024,
		    bytes / pkt);
	}

	public void printSummary(Pcap pcap) {
		PcapStat stats = new PcapStat();

		pcap.stats(stats);

		double pps = ((double) totPkt / ((double) (totTe - totTs) / 1000.));
		double bps = ((double) (totBytes * 8) / ((double) (totTe - totTs) / 1000.));

		System.out.printf(
		    "TOTAL: recv=%d, drop=%d, ifDrop=%d pps=%.2f bps=%.2fKb ave=%d bytes\n",
		    stats.getRecv(), stats.getDrop(), stats.getIfDrop(), pps, bps / 1024,
		    bytes / pkt);
	}


	public boolean hasDrops(Pcap pcap) {
		PcapStat stats = new PcapStat();

		pcap.stats(stats);

		if (stats.getDrop() != drops) {
			drops = stats.getDrop();

			return true;
		} else {
			return false;
		}
	}

	public void testCapture10() {
		StringBuilder errbuf = new StringBuilder();
		int snaplen = Pcap.DEFAULT_SNAPLEN;
		;
		int promisc = Pcap.MODE_PROMISCUOUS;
		int timeout = Pcap.DEFAULT_TIMEOUT;
		PcapIf dev;
		List<PcapIf> alldevs = new ArrayList<PcapIf>();

		if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
			fail(errbuf.toString());
		}

		final boolean verbose = ((System.getProperty("verbose") != null)
			? Boolean.parseBoolean(System.getProperty("verbose"))
			: false);
		final boolean doDispatch = ((System.getProperty("dispatch") != null)
			? Boolean.parseBoolean(System.getProperty("dispatch"))
			: false);

		int j = 0;
		for (PcapIf i : alldevs) {
			if (i.getDescription() == null) {
				if (verbose) {
					System.out.printf("#%d: %s\n", j, i.getName());
				}
			} else {
				if (verbose) {
					System.out.printf("#%d: %s - %s\n", j, i.getName(), i.getDescription());
				}
			}

			j++;
		}

		int index = 0;
		assertTrue("device count less then index " + index, alldevs.size() > index);
		dev = alldevs.get(index);

		if (verbose) {
			System.out.println();
			System.out.printf("Opening %s interface\n",
			    (dev.getDescription() != null) ? dev.getDescription() : dev.getName());
		}

		Pcap pcap = Pcap.openLive(dev.getName(), snaplen, promisc, timeout, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		final int max = ((System.getProperty("max") != null) 
			? Integer.parseInt(System.getProperty("max")) 
			: 1000);

		JBufferHandler<Pcap> handler = new JBufferHandler<Pcap>() {

			int cnt = 0;

			int next = 0;

			public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {
				if (cnt == next) {
					if (verbose) {
						System.out.printf((hasDrops(pcap) ? "X" : "."));
						System.out.flush();
					}

					next += (max / 10);
				}
				cnt++;
				pkt++;
				bytes += buffer.size();
			}

		};

		final int loops = ((System.getProperty("loops") != null) ? 
			Integer.parseInt(System.getProperty("loops")) 
			: 10);

		if (doDispatch == false) {
		for (int l = 0; l < loops; l++) {

			if (verbose) {
				System.out.printf("#%06d: ", l * max);
			}
			startStats();
			if (pcap.loop(max, handler, pcap) != Pcap.OK) {
				fail(pcap.getErr());
			}

			// pkt += max;
			// bytes += max * 1000;

			endStats();
			if (verbose) {
				System.out.printf("\n#%06d: ", l * max);
				printStats(pcap);
			}
		}
		} else {
		for (int l = 0; l < loops; l++) {

			if (verbose) {
				System.out.printf("#%06d: ", l * max);
			}
			startStats();
			int r, cnt = 0, calls = 0;
			
			while ( (r = pcap.dispatch(max, handler, pcap)) >= 0 && cnt < max) {
				if (r < 0) {
					fail(pcap.getErr());
				}

				cnt += r;
				calls ++;
			}

			// pkt += max;
			// bytes += max * 1000;


			endStats();
			if (verbose) {
				double ppc = (double)cnt / (double)calls; // Packets per Call
				System.out.printf("\n#%06d: calls=%d ppc=%.2f ", l * max, calls, ppc);
				printStats(pcap);
			}
		}
		}

		printSummary(pcap);

		pcap.close();
	}

}
