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
package org.jnetpcap.packet;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.header.MyHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestJScanner
    extends
    TestUtils {

	/** The flags. */
	private int[] flags;

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		flags = JRegistry.getAllFlags();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {

		JRegistry.setAllFlags(flags);
	}

	/**
	 * _test j scanner init.
	 */
	public void _testJScannerInit() {
		// May seem simple, but has detected a bug already in initializer :)
		new JScanner();
	}

	/**
	 * _test j scanner size of.
	 */
	public void _testJScannerSizeOf() {
		assertTrue("sizeof=" + JScanner.sizeof(), JScanner.sizeof() > 0
		    && JScanner.sizeof() < 100000);
	}

	/**
	 * _test scan one packet.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void _testScanOnePacket() throws IOException {
		JPacket packet = new JMemoryPacket(new byte[] {
		    (byte) 0xa0,
		    (byte) 0xa1,
		    (byte) 0xa2,
		    (byte) 0xa3,
		    (byte) 0xa4,
		    (byte) 0xa5,

		    (byte) 0xb0,
		    (byte) 0xb1,
		    (byte) 0xb2,
		    (byte) 0xb3,
		    (byte) 0xb4,
		    (byte) 0xb5,

		    (byte) 0x00,
		    (byte) 0x08, });

		JScanner scanner = new JScanner();
		scanner.scan(packet, Ethernet.ID);

		TextFormatter out = new TextFormatter();
		out.format(packet);
	}

	/**
	 * _test scan file bb handler.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void _testScanFileBBHandler() throws IOException {
		StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline("tests/test-l2tp.pcap", errbuf);

		final JPacket packet = new PcapPacket(Type.POINTER);
		final JScanner scanner = new JScanner();

		long start = System.currentTimeMillis();
		final TextFormatter out = new TextFormatter();

		pcap.loop(Pcap.LOOP_INFINITE, new ByteBufferHandler<String>() {
			int i = 0;

			public void nextPacket(PcapHeader header, ByteBuffer buffer, String user) {

				if (i == 200) {
					pcap.breakloop();
					return;
				}

				System.out.println("\nPacket #" + i);

				try {
					packet.peer(buffer);
				} catch (PeeringException e) {
					e.printStackTrace();
				}

				scanner.scan(packet, JProtocol.ETHERNET_ID);
				// try {
				out.setFrameIndex(i++);
				// out.format(packet);
				// System.out.println(packet.toString());
				// } catch (IOException e) {
				// // TODO Auto-generated catch block
				// e.printStackTrace();
				// }
			}

		}, "");

		long end = System.currentTimeMillis();

		System.out.printf("time=%d ms\n", (end - start));

		pcap.close();
	}

	/**
	 * _test scan file jb handler.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void _testScanFileJBHandler() throws IOException {
		StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline("tests/test-l2tp.pcap", errbuf);

		final JPacket packet = new PcapPacket(Type.POINTER);
		final JScanner scanner = new JScanner();

		long start = System.currentTimeMillis();
		final TextFormatter out = new TextFormatter();

		pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<String>() {
			int i = 0;

			public void nextPacket(PcapHeader header, JBuffer buffer, String user) {

				if (i == 200) {
					pcap.breakloop();
					return;
				}

				System.out.println("\nPacket #" + i);

				packet.peer(buffer);

				scanner.scan(packet, JProtocol.ETHERNET_ID);
				// try {
				out.setFrameIndex(i++);
				// out.format(packet);
				// System.out.println(packet.toString());
				// } catch (IOException e) {
				// // TODO Auto-generated catch block
				// e.printStackTrace();
				// }
			}

		}, "");

		long end = System.currentTimeMillis();

		System.out.printf("time=%d ms\n", (end - start));

		pcap.close();
	}

	/**
	 * Test scan file jp handler.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testScanFileJPHandler() throws IOException {
		StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline("tests/test-vlan.pcap", errbuf);

		// long start = System.currentTimeMillis();
		@SuppressWarnings("unused")
		final TextFormatter out = new TextFormatter();
		@SuppressWarnings("unused")
		final JScanner scanner = new JScanner();

		pcap.loop(Pcap.LOOP_INFINITE, JProtocol.ETHERNET_ID,
		    new JPacketHandler<String>() {
			    @SuppressWarnings("unused")
			    int i = 0;

			    public void nextPacket(JPacket packet, String user) {

				    // scanner.scan(packet, JProtocol.ETHERNET_ID);
				    // try {
				    // out.setFrameIndex(i++);
				    // out.format(packet);
				    // } catch (IOException e) {
				    // e.printStackTrace();
				    // }
			    }

		    }, "");

		// long end = System.currentTimeMillis();

		// System.out.printf("time=%d ms\n", (end - start));

		pcap.close();
	}

	/**
	 * Test scanner constructor annotated my header class.
	 */
	public void testScannerConstructorAnnotatedMyHeaderClass() {

		new JHeaderScanner(MyHeader.class);
	}

	/**
	 * Test invoke get header length annotated.
	 */
	public void testInvokeGetHeaderLengthAnnotated() {

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		JHeaderScanner scanner = new JHeaderScanner(MyHeader.class);

		assertEquals(20, scanner.getHeaderLength(packet, Ethernet.LENGTH));

		System.out.printf("length=%d %d\n", scanner.getHeaderLength(packet,
		    Ethernet.LENGTH), packet.getUByte(Ethernet.LENGTH) & 0x0F);
	}

	/**
	 * Test flag non override.
	 */
	public void testFlagNonOverride() {
		PcapPacket packet = getPcapPacket(HTTP, 5);

		assertTrue(packet.hasHeader(JProtocol.ETHERNET_ID));
		assertTrue(packet.hasHeader(JProtocol.IP4_ID));
		assertTrue(packet.hasHeader(JProtocol.TCP_ID));
		assertTrue(packet.hasHeader(JProtocol.HTTP_ID));
	}

	/**
	 * Test flag override.
	 */
	public void testFlagOverride() {
		JScanner.bindingOverride(JProtocol.TCP_ID, true);
		JScanner.heuristicCheck(JProtocol.TCP_ID, false);
		JPacket.getDefaultScanner().reloadAll();

		PcapPacket packet = getPcapPacket(HTTP, 5);

		assertTrue(packet.hasHeader(JProtocol.ETHERNET_ID));
		assertTrue(packet.hasHeader(JProtocol.IP4_ID));
		assertTrue(packet.hasHeader(JProtocol.TCP_ID));
		assertFalse(packet.hasHeader(JProtocol.HTTP_ID));
		
		JScanner.heuristicCheck(JProtocol.TCP_ID, true);
		JPacket.getDefaultScanner().reloadAll();

	}

	/**
	 * Test flag post heuristics.
	 */
	public void testFlagPostHeuristics() {
		JScanner.bindingOverride(JProtocol.TCP_ID, true);
		JScanner.heuristicPostCheck(JProtocol.TCP_ID, true);

		PcapPacket packet = getPcapPacket(HTTP, 5);

		assertTrue(packet.hasHeader(JProtocol.ETHERNET_ID));
		assertTrue(packet.hasHeader(JProtocol.IP4_ID));
		assertTrue(packet.hasHeader(JProtocol.TCP_ID));
		assertTrue(packet.hasHeader(JProtocol.HTTP_ID));
	}

	/**
	 * Test packet state.
	 */
	public void testPacketState() {

		PcapPacket packet = getPcapPacket(HTTP, 5);
		assertNotNull(packet);

		System.out.println(packet.getState().toDebugString());
	}

	/**
	 * Test get frame number.
	 */
	public void testGetFrameNumber() {
		assertTrue(JScanner.getThreadLocal().getFrameNumber() != 0);
		System.out.printf("frameNumber=%d\n", JScanner.getThreadLocal()
		    .getFrameNumber());
	}

	/**
	 * Test set frame number.
	 */
	public void testSetFrameNumber() {
		long n = JScanner.getThreadLocal().getFrameNumber();

		JScanner.getThreadLocal().setFrameNumber(n + 1);

		assertEquals(n + 1, JScanner.getThreadLocal().getFrameNumber());

		System.out.printf("frameNumber=%d\n", JScanner.getThreadLocal()
		    .getFrameNumber());

	}

}
