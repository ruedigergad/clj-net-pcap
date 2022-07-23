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
package org.jnetpcap.winpcap;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapPktHdr;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class TestWinPcapExtensions
    extends TestCase {

	/** The Constant device. */
	private final static String device = "\\Device\\NPF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D}";

//	private final static String uri = "rpcap://[192.168.1.100]/\\Device\\NPF_{04BD71F0-BAD6-4C51-96A4-B05562FAD4F9}";

	/** The Constant rdevice. */
private final static String rdevice = "\\Device\\NPF_{04BD71F0-BAD6-4C51-96A4-B05562FAD4F9}";

	/** The Constant rhost. */
	private final static String rhost = "192.168.1.100";

	/** The Constant fname. */
	private final static String fname = "tests/test-l2tp.pcap";

//	private static final int OK = 0;

	/** The Constant snaplen. */
private static final int snaplen = 64 * 1024;

	/** The Constant flags. */
	private static final int flags = Pcap.MODE_PROMISCUOUS;

	/** The Constant promisc. */
	private static final int promisc = 1;

	/** The Constant oneSecond. */
	private static final int oneSecond = 1000;

	/** The errbuf. */
	private StringBuilder errbuf;

	/** The do nothing handler. */
	private final PcapHandler<?> doNothingHandler = new PcapHandler<Object>() {

		public void nextPacket(Object userObject, long seconds, int useconds,
		    int caplen, int len, ByteBuffer buffer) {
			// Do nothing handler
		}
	};

	/** The print timestamp handler. */
	private PcapHandler<String> printTimestampHandler;

	/** The tmp file. */
	private static File tmpFile;

	static {
		try {
			tmpFile = File.createTempFile("temp-", "-TestPcapJNI");
		} catch (IOException e) {
			tmpFile = null;
		}

	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {

		errbuf = new StringBuilder();

		printTimestampHandler = new PcapHandler<String>() {
			private int i = 0;

			public void nextPacket(String msg, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {
				Date ts = new Date(seconds * 1000);

				msg = (msg == null) ? "captured on" : msg;

				System.out.printf("Packet #%d %s %s (cap=%d, len=%d)\n", i++, msg, ts,
				    caplen, len);
			}
		};

	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		if (tmpFile.exists()) {
			assertTrue(tmpFile.delete());
		}
	}

	/**
	 * Test is win pcap ext supported.
	 */
	public void testIsWinPcapExtSupported() {
		String os = System.getProperty("os.name");

		/*
		 * WinPcap is only available on windows based systems.
		 */
		if (os.startsWith("Windows")) {
			assertTrue(WinPcap.isSupported());
		} else {
			assertFalse(WinPcap.isSupported());
		}
	}

	/**
	 * Test disabled, as it requires live packets to capture. To enable the test
	 * just rename the method, by removing the prefix SKIP. Then make sure there
	 * are live packets to be captured.
	 */
	public void SKIPtestOpenLiveAndDispatch() {

		WinPcap winPcap = WinPcap.openLive(device, 10000, 1, 60 * 1000, errbuf);
		assertNotNull(winPcap);

		PcapHandler<String> handler = new PcapHandler<String>() {

			public void nextPacket(String user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

				System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
				    .toString(), new Date(seconds * 1000).toString(), caplen, len,
				    buffer.capacity());
			}
		};

		winPcap.dispatch(10, handler, "Hello");

		winPcap.close();
	}

	/**
	 * SKI ptest win pcap stats.
	 */
	public void SKIPtestWinPcapStats() {

		WinPcap pcap = WinPcap
		    .openLive(device, snaplen, promisc, oneSecond, errbuf);

		pcap.loop(50, doNothingHandler, null);

		WinPcapStat stats = pcap.statsEx();

		System.out.printf("stats=%s\n", stats.toString());

		pcap.close();

	}

	/**
	 * Test send queue depracated.
	 */
  public void testSendQueueDepracated() {
		WinPcapSendQueue queue = WinPcap.sendQueueAlloc(512);

		WinPcap pcap = WinPcap
		    .openLive(device, snaplen, promisc, oneSecond, errbuf);

		byte[] pkt = new byte[128];
		Arrays.fill(pkt, (byte) 255);

		PcapPktHdr hdr = new PcapPktHdr(128, 128);
		queue.queue(hdr, pkt); // Packet #1
		queue.queue(hdr, pkt); // Packet #2

		Arrays.fill(pkt, (byte) 0x11);
		queue.queue(hdr, pkt); // Packet #3
		int r = pcap.sendQueueTransmit(queue, WinPcap.TRANSMIT_SYNCH_ASAP);
		if (r != queue.getLen()) {

			assertEquals("transmit() call failed [", queue.getLen(), r);
		}

		pcap.close();

		WinPcap.sendQueueDestroy(queue);
	}
	
  /**
	 * Test send queue.
	 */
  public void testSendQueue() {
		WinPcapSendQueue queue = WinPcap.sendQueueAlloc(512);

		WinPcap pcap = WinPcap
		    .openLive(device, snaplen, promisc, oneSecond, errbuf);

		byte[] pkt = new byte[128];
		Arrays.fill(pkt, (byte) 255);

		PcapHeader hdr = new PcapHeader(128, 128);
		queue.queue(hdr, pkt); // Packet #1
		queue.queue(hdr, pkt); // Packet #2

		Arrays.fill(pkt, (byte) 0x11);
		queue.queue(hdr, pkt); // Packet #3
		int r = pcap.sendQueueTransmit(queue, WinPcap.TRANSMIT_SYNCH_ASAP);
		if (r != queue.getLen()) {

			assertEquals("transmit() call failed [", queue.getLen(), r);
		}

		pcap.close();

		WinPcap.sendQueueDestroy(queue);
	}


	/**
	 * Test set sampling live.
	 */
	public void testSetSamplingLive() {

		// Only setSampling only supported on live captures
		WinPcap pcap = WinPcap
		    .openLive(device, snaplen, promisc, oneSecond, errbuf);
		assertNotNull(pcap);

		WinPcapSamp samp = pcap.setSampling();
		assertNotNull(samp);

		assertEquals("method", 0, samp.getMethod());

		samp.setMethod(WinPcapSamp.FIRST_AFTER_N_MS);
		samp.setValue(10); // 10ms
		assertEquals("method", 2, samp.getMethod());
		pcap.close();
	}

	/**
	 * Test set sampling offline.
	 */
	public void testSetSamplingOffline() {

		// Only setSampling only supported on live captures
		WinPcap pcap = WinPcap.openOffline(fname, errbuf);
		assertNotNull(pcap);

		WinPcapSamp samp = pcap.setSampling();
		assertNotNull(samp);

		assertEquals("method", 0, samp.getMethod());

		samp.setMethod(WinPcapSamp.FIRST_AFTER_N_MS);
		samp.setValue(10); // 10ms
		assertEquals("method", 2, samp.getMethod());
		pcap.close();
	}

	/**
	 * SKI ptest find all devs ex.
	 */
	public void SKIPtestFindAllDevsEx() {
		String source = "rpcap://192.168.1.100/";
		List<PcapIf> ifs = new ArrayList<PcapIf>();
		WinPcapRmtAuth auth = new WinPcapRmtAuth();

		int r = WinPcap.findAllDevsEx(source, auth, ifs, errbuf);
		assertEquals(errbuf.toString(), 0, r);

		assertFalse("expected to find some devices", ifs.isEmpty());
		// System.out.printf("ifs=%s\n", ifs);
	}

	/**
	 * SKI ptest remote open.
	 */
	public void SKIPtestRemoteOpen() {

		StringBuilder source = new StringBuilder();
		int r = WinPcap.createSrcStr(source, WinPcap.SRC_IFREMOTE, rhost, null,
		    rdevice, errbuf);
		if (r != Pcap.OK) {
			fail(errbuf.toString());
		} else {
			System.out.printf("source=%s\n", source);
		}

		WinPcap pcap = WinPcap.open(source.toString(), snaplen, flags, oneSecond,
		    null, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(10, printTimestampHandler, null);

		pcap.close();
	}

	/**
	 * Test live dump.
	 */
	public void testLiveDump() {

		System.out.printf("tmpFile=%s\n", tmpFile.getAbsoluteFile());

		WinPcap pcap = WinPcap
		    .openLive(device, snaplen, promisc, oneSecond, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		int r = pcap.liveDump(tmpFile.getAbsolutePath(), 100 * 1024, 10);
		assertEquals(pcap.getErr(), 0, r);

		pcap.liveDumpEnded(1); // Wait for dump to finish

		assertTrue("Empty dump file " + tmpFile.getAbsolutePath(),
		    tmpFile.length() > 0);
		pcap.close();

	}
}
