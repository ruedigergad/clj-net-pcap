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
package org.jnetpcap.protocol;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Tcp.Flag;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.DataUtils;
import org.jnetpcap.util.PcapPacketArrayList;
import org.jnetpcap.util.checksum.Checksum;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class TestTcpIp extends TestUtils {

	/** The Constant HTTP_IP6. */
	public final static String HTTP_IP6 = "tests/v6-http.cap";

	/** The Constant SMALL_IMAP. */
	public final static String SMALL_IMAP = "tests/test-small-imap.pcap";

	/**
	 * Test ip4 cr c16 pkt1.
	 */
	public void testIp4CRC16Pkt1() {

		JPacket packet = super.getPcapPacket(TestUtils.L2TP, 0);
		Ip4 ip = packet.getHeader(new Ip4());

		int computed = Checksum.inChecksum(ip, 0, ip.size());

		System.out.printf("1chunk=%x\n", computed);
		System.out.printf("shoudbe=%x checksum=%x\n",
				Checksum.inChecksumShouldBe(ip.checksum(), computed),
				ip.checksum());

		assertTrue(ip.isChecksumValid());
	}

	/**
	 * Test ip4 cr c16 pkt2.
	 */
	public void testIp4CRC16Pkt2() {

		JPacket packet = super.getPcapPacket(TestUtils.L2TP, 1);
		Ip4 ip = packet.getHeader(new Ip4());

		assertEquals(ip.calculateChecksum(), ip.checksum());
	}

	/**
	 * Test ip4 cr c16 pkt50.
	 */
	public void testIp4CRC16Pkt50() {

		JPacket packet = super.getPcapPacket(TestUtils.L2TP, 46 - 1);
		Ip4 ip = packet.getHeader(new Ip4());

		int crc;
		assertEquals(ip.checksum(), ip.calculateChecksum());

		// System.out.printf("ip.crc=%x computed=%x\n", ip.checksum(), crc);
	}

	/**
	 * Test ip4 cr c16 entire file.
	 * 
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	public void testIp4CRC16EntireFile() throws InterruptedException {
		Ip4 ip = new Ip4();
		for (JPacket packet : super.getIterable(TestUtils.L2TP)) {
			Thread.sleep(10);
			long f = packet.getFrameNumber() + 1;
			assertTrue(packet.hasHeader(ip));

			assertEquals(20, ip.size());
			final int crc = ip.calculateChecksum();

			if (ip.checksum() != crc) {
				try {
					System.out.println(packet.getState().toDebugString());
					System.out.println(packet);
				} catch (Exception e) {
					System.out.println(packet.getState().toDebugString());
					e.printStackTrace();
				}
				System.out.printf("#%d: ip.crc=%x computed=%x\n", f,
						ip.checksum(), crc);
				System.out.println(ip.toHexdump());
			}

			assertEquals("Frame #" + f, ip.checksum(), crc);
		}
	}

	/**
	 * Test ip4 cr c16 using handler.
	 */
	public void testIp4CRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(TestUtils.L2TP, errbuf);

		assertNotNull(pcap);

		pcap.dispatch(Pcap.DISPATCH_BUFFER_FULL, JProtocol.ETHERNET_ID,
				new PcapPacketHandler<Pcap>() {
					Ip4 ip = new Ip4();

					int i = 0, j = 0;

					// public void nextPacket(PcapHeader header, JBuffer buffer,
					// String
					// user)
					// {
					public void nextPacket(PcapPacket packet, Pcap pcap) {

						// if (i++ % 1 == 0) {
						// packet = new PcapPacket(packet);
						j++;
						// }

						long f = packet.getFrameNumber();
						assertTrue("#" + f, packet.hasHeader(ip));
						System.out.println(packet.getState().toDebugString());

						assertTrue("Frame #" + f, ip.isChecksumValid());
					}

				}, null);
	}

	/**
	 * Test compare2 sets of packets.
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void testCompare2SetsOfPackets() throws IOException {
		List<PcapPacket> l1 = getPacketList(L2TP);
		List<PcapPacket> l2 = getPacketList(L2TP);

		assertEquals(l1.size(), l2.size());

		for (int i = 0; i < l1.size(); i++) {
			PcapPacket p1 = l1.get(i);
			PcapPacket p2 = l2.get(i);

			if (p1.size() != p2.size()) {
				System.out.printf("#%d p1=%d p2=%d\n%s\n%s\n", i, l1.size(),
						l2.size(), p1.toHexdump(), p2.toHexdump());

				System.out.println(p1.toString());
				System.out.println(p2.toString());
			}

			assertEquals(p1.size(), p2.size());
			assertTrue(compareJBuffer(p1, p2));

		}

	}

	/**
	 * Test compare checksum of2 sets.
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void testCompareChecksumOf2Sets() throws IOException {
		List<PcapPacket> l1 = getPacketList(L2TP);
		List<PcapPacket> l2 = getPacketList(L2TP);

		assertEquals(l1.size(), l2.size());

		Ip4 ip1 = new Ip4();
		Ip4 ip2 = new Ip4();

		for (int i = 0; i < l1.size(); i++) {
			PcapPacket p1 = l1.get(i);
			PcapPacket p2 = l2.get(i);

			int c1 = p1.getHeader(ip1).calculateChecksum();
			int c2 = p2.getHeader(ip2).calculateChecksum();

			System.out.println(ip1);
			System.out.println(ip2);

			assertEquals(c1, ip1.checksum());
			assertEquals(c2, ip2.checksum());

			assertEquals(c1, c2);
		}

	}

	/**
	 * Compare j buffer.
	 * 
	 * @param b1
	 *            the b1
	 * @param b2
	 *            the b2
	 * @return true, if successful
	 */
	private boolean compareJBuffer(JBuffer b1, JBuffer b2) {
		if (b1.size() != b2.size()) {
			return false;
		}

		for (int i = 0; i < b1.size(); i++) {
			if (b1.getByte(i) != b2.getByte(i)) {
				return false;
			}
		}

		return true;
	}

	/** The checksums. */
	List<Integer> checksums = new ArrayList<Integer>();

	/** The saved. */
	List<Integer> saved = new ArrayList<Integer>();

	/** The data. */
	List<byte[]> data = new ArrayList<byte[]>();

	/**
	 * Gets the packet list.
	 * 
	 * @param file
	 *            the file
	 * @return the packet list
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	private List<PcapPacket> getPacketList(String file) throws IOException {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(file, errbuf);
		if (pcap == null) {
			throw new IOException(errbuf.toString());
		}

		final PcapPacketArrayList list = new PcapPacketArrayList(
				(int) new File(file).length() / 100);

		pcap.loop(Pcap.LOOP_INFINITE, list, null);

		pcap.close();

		return list;
	}

	/**
	 * Test ip checksum.
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void testIpChecksum() throws IOException {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(L2TP, errbuf);
		if (pcap == null) {
			throw new IOException(errbuf.toString());
		}

		assertTrue(pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<Pcap>() {
			Ip4 ip1 = new Ip4();

			Ip4 ip2 = new Ip4();

			int i = 0;

			public void nextPacket(PcapPacket p1, Pcap user) {
				i++;
				p1.getHeader(ip1);
				int c1 = ip1.calculateChecksum();

				PcapPacket p2 = new PcapPacket(p1);
				p2.getHeader(ip2);

				int c2 = ip2.calculateChecksum();

				if (c1 != c2) {
					System.out.printf("#%d crc_before=%x crc_after=%x\n", i,
							c1, c2);
					System.out
							.printf("P1: %s\nheader1=%s\n\nstate1=%s\npacket1=%s\n\nip1=%s\n",
									p1.toHexdump(), p1.getCaptureHeader()
											.toDebugString(), p1.getState()
											.toDebugString(), p1
											.toDebugString(), ip1
											.toDebugString());

					System.out.println("---------------------------");

					System.out
							.printf("P2: %s\nheader2=%s\n\nstate2=%s\npacket2=%s\n\nip2=%s\n\n",
									p2.toHexdump(), p2.getCaptureHeader()
											.toDebugString(), p2.getState()
											.toDebugString(), p2
											.toDebugString(), ip2
											.toDebugString());

					System.out.println("p1-p2.memory.diff=\n"
							+ FormatUtils.hexdump(DataUtils.diff(p1, p2)));

					System.out.println("ip1-ip2.memory.diff=\n"
							+ FormatUtils.hexdump(DataUtils.diff(ip1, ip2)));

					user.breakloop();
				}

				i++;
			}

		}, pcap) != -2);

		pcap.close();
	}

	/**
	 * Test compare2 sets of packets2.
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void testCompare2SetsOfPackets2() throws IOException {
		List<PcapPacket> l1 = getPacketList(L2TP);
		List<PcapPacket> l2 = getPacketList(L2TP);
		Ip4 ip1 = new Ip4();
		Ip4 ip2 = new Ip4();

		assertEquals(l1.size(), l2.size());

		System.out.println("------------------------------\n");

		for (int i = 0; i < l1.size(); i++) {
			PcapPacket p1 = l1.get(i);
			PcapPacket p2 = l2.get(i);
			p1.getHeader(ip1);
			p2.getHeader(ip2);

			assertTrue("ip1.size() == p2.size()", p1.size() == p2.size());

			assertTrue(ip1.toString(), ip1.isChecksumValid());
			assertTrue(ip2.toString(), ip2.isChecksumValid());
			assertTrue(compareJBuffer(p1, p2));

		}

	}

	/**
	 * Test tcp ip4 cr c16 using handler.
	 */
	public void testTcpIp4CRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(TestUtils.HTTP, errbuf);

		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<String>() {
			Ip4 ip = new Ip4();

			Tcp tcp = new Tcp();

			// public void nextPacket(PcapHeader header, JBuffer buffer, String
			// user)
			// {
			public void nextPacket(PcapPacket packet, String user) {

				if (packet.hasHeader(tcp) == false) {
					return;
				}

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				final int crc = Checksum.pseudoTcp(packet, ip.getOffset(),
						tcp.getOffset());

				if (crc != 0 && tcp.checksum() != crc) {
					System.out.println(tcp);
					System.out.printf("#%d: tcp.crc=%x computed=%x\n", f,
							tcp.checksum(), crc);
					// System.out.println(ip.toHexdump());
					// System.out.println(tcp.toHexdump());
					System.exit(0);
				}

				// assertEquals("Frame #" + f, tcp.checksum(), crc);
			}

		}, null);
	}

	/**
	 * Test tcp ip6 cr c16 using handler.
	 */
	public void testTcpIp6CRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(HTTP_IP6, errbuf);

		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<String>() {
			Ip6 ip = new Ip6();

			Tcp tcp = new Tcp();

			public void nextPacket(PcapPacket packet, String user) {

				if (packet.hasHeader(tcp) == false) {
					return;
				}
				System.out.println(packet.toString());

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				assertTrue("Frame #" + f, tcp.isChecksumValid());
			}

		}, null);
	}

	/**
	 * Test udp ip6 cr c16 using handler.
	 */
	public void testUdpIp6CRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(HTTP_IP6, errbuf);

		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<String>() {
			Ip6 ip = new Ip6();

			Udp udp = new Udp();

			public void nextPacket(PcapPacket packet, String user) {

				if (packet.hasHeader(udp) == false) {
					return;
				}

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				assertTrue("Frame #" + f, udp.isChecksumValid());
			}

		}, null);
	}

	/**
	 * Test icmp cr c16 using handler.
	 */
	public void testIcmpCRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(TestTcpIp.VLAN, errbuf);

		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<String>() {
			Ip4 ip = new Ip4();

			Icmp icmp = new Icmp();

			public void nextPacket(PcapPacket packet, String user) {

				if (packet.hasHeader(icmp) == false) {
					return;
				}

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				if (icmp.isChecksumValid() == false) {
					System.out.printf("#%d shouldbe=%x checksum=%x\n", f,
							icmp.calculateChecksum(), icmp.checksum());
				}

				assertTrue("#" + f, icmp.isChecksumValid());
			}

		}, null);
	}

	/**
	 * Test ip4 fragment flag directly.
	 */
	public void testIp4FragmentFlagDirectly() {
		JPacket packet = TestUtils.getPcapPacket(TestUtils.REASEMBLY, 1 - 1);
		Ethernet eth = new Ethernet();

		if (packet.hasHeader(eth)) {
			// System.out.println(eth);
			// System.out.printf("flags=%x\n", eth.getState().getFlags());
			assertNotSame(JHeader.State.FLAG_HEADER_FRAGMENTED, (eth.getState()
					.getFlags() & JHeader.State.FLAG_HEADER_FRAGMENTED));
		}

		Ip4 ip = new Ip4();
		if (packet.hasHeader(ip)) {
			// System.out.println(ip);
			// System.out.printf("flags=%x\n", ip.getState().getFlags());
			assertEquals(JHeader.State.FLAG_HEADER_FRAGMENTED, (ip.getState()
					.getFlags() & JHeader.State.FLAG_HEADER_FRAGMENTED));
		}

		Icmp icmp = new Icmp();
		if (packet.hasHeader(icmp)) {
			// System.out.println(icmp);
			// System.out.printf("flags=%x\n", icmp.getState().getFlags());
			assertEquals(JHeader.State.FLAG_HEADER_FRAGMENTED, (icmp.getState()
					.getFlags() & JHeader.State.FLAG_HEADER_FRAGMENTED));
		}

	}

	/**
	 * Test j header is fragmented.
	 */
	public void testJHeaderIsFragmented() {
		JPacket packet = TestUtils.getPcapPacket(TestUtils.REASEMBLY, 1 - 1);
		Ethernet eth = new Ethernet();

		if (packet.hasHeader(eth)) {
			assertFalse(eth.isFragmented());
		}

		Ip4 ip = new Ip4();
		if (packet.hasHeader(ip)) {
			assertTrue(ip.isFragmented());
		}

		Icmp icmp = new Icmp();
		if (packet.hasHeader(icmp)) {
			assertTrue(ip.isFragmented());
		}

	}

	/**
	 * Test tcp options.
	 * 
	 * <pre>
	 * 
	 * </pre>
	 */
	public void testTcpOptions() {
		JPacket packet = TestUtils.getPcapPacket(SMALL_IMAP, 1 - 1);
		System.out.println(packet.getState().toDebugString());
		System.out.println(packet.toString());

		Tcp tcp = packet.getHeader(new Tcp());
		Tcp.Timestamp ts = new Tcp.Timestamp();

		if (tcp.hasSubHeader(ts)) {
			System.out.printf("tsval=%d tsecr=%d%n", ts.tsval(), ts.tsecr());
		}
	}

	/**
	 * Bug#3321797
	 * 
	 * <pre>
	 * Details:
	 * I use the following snippet to reproduce the bug.
	 * I hope the information is sufficient for you to track it down.
	 * Thanks a lot for this very nice software!
	 * 
	 * </pre>
	 */
	public void testFlagsToEnumSet() {
		/*
		 * 
		 * From org.jnetpcap.protocol.tcpip.Tcp
		 * 
		 * The Constant FLAG_ACK. private static final int FLAG_ACK = 0x10;
		 * 
		 * ...
		 * 
		 * The Constant FLAG_SYN. private static final int FLAG_SYN = 0x02;
		 */
		int flags = 0x02 | 0x10;

		Set<Tcp.Flag> flagSet = Tcp.Flag.asSet(flags);

		assertEquals("[SYN, ACK]", flagSet.toString());
		assertEquals(EnumSet.of(Flag.ACK, Flag.SYN), flagSet);

		/*
		 * Result: java.lang.AssertionError: expected:<[ACK, SYN]> but
		 * was:<[CWR, PSH]> ...
		 * 
		 * JNetPcap Version: jnetpcap-1.4.r1300-1
		 */
	}

}
