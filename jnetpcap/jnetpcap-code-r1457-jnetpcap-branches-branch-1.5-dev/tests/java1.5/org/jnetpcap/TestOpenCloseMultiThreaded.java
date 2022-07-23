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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Exchanger;

import junit.framework.TestCase;

import org.jnetpcap.winpcap.WinPcap;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class TestOpenCloseMultiThreaded
    extends TestCase {

	/** The looping. */
	private boolean looping = false;

	/** The callback. */
	private final PcapHandler<Pcap> callback = new PcapHandler<Pcap>() {

		public void nextPacket(Pcap pcap, long seconds, int useconds, int caplen,
		    int len, ByteBuffer buffer) {

			if (looping == false) {
				try {
					exchanger.exchange(pcap);
				} catch (InterruptedException e) {
					System.out
					    .println("Exchange of pcap between threads failed in child thread");
					System.exit(1);
				}
				looping = true;
			}
		}
	};

	/** The exchanger. */
	private final Exchanger<Pcap> exchanger = new Exchanger<Pcap>();

	/**
	 * Open and loop.
	 * 
	 * @return the pcap
	 */
	private Pcap openAndLoop() {

		looping = false;
		final List<PcapIf> alldevs = new ArrayList<PcapIf>();
		final StringBuilder errbuf = new StringBuilder();
		Pcap.findAllDevs(alldevs, errbuf);

		// System.out.println(alldevs);

		final WinPcap pcap =
		    WinPcap.openLive(alldevs.get(0).getName(), 65 * 1024, 1, 0, errbuf);
		pcap.setMinToCopy(0);

		pcap.loop(0, callback, pcap);

		return pcap;
	}

	/**
	 * Test1.
	 * 
	 * @throws InterruptedException
	 *           the interrupted exception
	 */
	public void test1() throws InterruptedException {

		final int COUNT = 30;

		for (int i = 0; i < COUNT; i++) {
			// System.out.println("Loop #" + i);

			final Thread t = new Thread(new Runnable() {

				public void run() {
					openAndLoop();
				}

			});

			t.start();

			final Pcap pcap = exchanger.exchange(null);
			pcap.breakloop();
			t.join();
			pcap.close();

		}

	}

}
