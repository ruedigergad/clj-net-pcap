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

import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JHandlerTest extends TestCase implements
		ByteBufferHandler<String>, JBufferHandler<String>,
		JPacketHandler<String> {

	/** The ethernet. */
	private Ethernet ethernet = new Ethernet();

	/** The ip4. */
	private Ip4 ip4 = new Ip4();

	/** The ip6. */
	private Ip6 ip6 = new Ip6();

	/** The packet. */
	private PcapPacket packet = new PcapPacket(Type.POINTER);

	/** The scanner. */
	private JScanner scanner = new JScanner();

	/** The pcap. */
	private Pcap pcap;

	@Override
	protected void setUp() throws Exception {

		pcap = TestUtils.openOffline("tests/test-afs.pcap");
		assertNotNull(pcap);
	}

	@Override
	protected void tearDown() throws Exception {
		assertNotNull(pcap);
		pcap.close();
	}

	/**
	 * Test j scanner handler.
	 */
	public void testJScannerHandler() {
		pcap.dispatch(2,
				JProtocol.ETHERNET_ID,
				(JPacketHandler<String>) this,
				"JPacket - testcase");
	}

	/**
	 * Test j buffer handler.
	 */
	public void AtestJBufferHandler() {
		pcap.dispatch(2, (JBufferHandler<String>) this, "JBuffer - testcase");
	}

	/**
	 * Test pcap handler.
	 */
	public void AtestPcapHandler() {
		pcap.dispatch(2,
				(ByteBufferHandler<String>) this,
				"Pcap handler - testcase");
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JBufferHandler#nextPacket(org.jnetpcap.PcapHeader, org.jnetpcap.nio.JBuffer, java.lang.Object)
	 */
	public void nextPacket(PcapHeader pcapHdr, JBuffer jbuf, String user) {

		// packet.peerHeaderAndData(pcapHdr, jbuf);
		// scanner.scan(packet, Ethernet.ID);
		//
		// assertTrue(packet.getPacketWirelen() > 0);

		// System.out.printf("JHandlerTest::nextPacket() - %s\n",
		// packet.getState()
		// .toDebugString());
		//
		// if (packet.hasHeader(ethernet)) {
		// System.out.println("ethernet.dst=" + ethernet.destination());
		// }
		//
		// if (packet.hasHeader(ip4)) {
		// System.out.println("ip4.ver=" + ip4.version());
		// }
		//
		// if (packet.hasHeader(ip6)) {
		// System.out.println("ip4.ver=" + ip4.version());
		// }
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JScannerHandler#nextPacket(org.jnetpcap.PcapHeader,
	 *      org.jnetpcap.packet.JPacket, java.lang.Object)
	 */
	public void nextPacket(JPacket packet, String user) {

		// System.out.printf("state=%s", packet.getState().toDebugString());
		System.out.printf("packet=%s", packet.toString());

		// if (packet.hasHeader(ethernet)) {
		// System.out.println("ethernet.dst="
		// + FormatUtils.asString(ethernet.destination(), ':'));
		// }
		//
		// if (packet.hasHeader(ip4)) {
		// System.out.println("ip4.ver=" + ip4.version());
		// }
		//
		// if (packet.hasHeader(ip6)) {
		// System.out.println("ip4.ver=" + ip4.version());
		// }
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.PcapHandler#nextPacket(java.lang.Object, long, int, int,
	 *      int, java.nio.ByteBuffer)
	 */
	public void nextPacket(PcapHeader header, ByteBuffer bytebuffer, String user) {

		// try {
		// packet.peerHeaderAndData(header, bytebuffer);
		// } catch (PeeringException e) {
		// e.printStackTrace();
		// }
		// scanner.scan(packet, Ethernet.ID);

		// if (packet.hasHeader(ethernet)) {
		// System.out.println("ethernet.dst=" + ethernet.destination());
		// }
		//
		// if (packet.hasHeader(ip4)) {
		// System.out.println("ip4.ver=" + ip4.version());
		// }
		//
		// if (packet.hasHeader(ip6)) {
		// System.out.println("ip4.ver=" + ip4.version());
		// }

	}
}
