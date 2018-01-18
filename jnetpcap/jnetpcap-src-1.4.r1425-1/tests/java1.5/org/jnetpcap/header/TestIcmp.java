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
package org.jnetpcap.header;

import java.io.IOException;

import junit.framework.TestCase;

import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Icmp.IcmpType;
import org.jnetpcap.protocol.tcpip.Udp;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestIcmp
    extends TestCase {

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	/**
	 * Packet dump:
	 * 
	 * <pre>
	 * Ethernet:  ******* Ethernet (Eth) offset=0 length=14
	 * 	Ethernet: 
	 * 	Ethernet:      destination = 16-03-78-01-16-03
	 * 	Ethernet:           source = 00-60-08-9F-B1-F3
	 * 	Ethernet:         protocol = 0x800 (2048) [ip version 4]
	 * 	Ethernet: 
	 * 	ip4:  ******* ip4 (ip) offset=14 length=20
	 * 	ip4: 
	 * 	ip4:          version = 4
	 * 	ip4:             hlen = 5 [*4 = 20 bytes]
	 * 	ip4:            diffs = 0xC0 (192)
	 * 	ip4:                    1100 00..  = [48] reserved bit: code point 48
	 * 	ip4:                    .... ..0.  = [0] ECN bit: ECN capable transport: no
	 * 	ip4:                    .... ...0  = [0] ECE bit: ECE-CE: no
	 * 	ip4:           length = 468
	 * 	ip4:            flags = 0x0 (0)
	 * 	ip4:                    0..  = [0] reserved bit: not set
	 * 	ip4:                    .0.  = [0] don't fragment: not set
	 * 	ip4:                    ..0  = [0] more fragments: not set
	 * 	ip4:               id = 0xE253 (57939)
	 * 	ip4:           offset = 0
	 * 	ip4:     time to live = 255 router hops
	 * 	ip4:         protocol = 1 [icmp - internet message control protocol]
	 * 	ip4:  header checksum = 0xAE96 (44694)
	 * 	ip4:           source = 131.151.32.21
	 * 	ip4:      destination = 131.151.1.59
	 * 	ip4: 
	 * 	icmp:  ******* icmp (icmp) offset=34 length=8
	 * 	icmp: 
	 * 	icmp:             type = 3 [destination unreachable]
	 * 	icmp:             code = 3 [destination port unreachable]
	 * 	icmp:         checksum = 0x2731 (10033)
	 * 	icmp: 
	 * 	icmp: + DestUnreachable: offset=4 length=4
	 * 	icmp:         reserved = 0
	 * 	icmp: 
	 * 	ip4:  ******* ip4 (ip) offset=42 length=20
	 * 	ip4: 
	 * 	ip4:          version = 4
	 * 	ip4:             hlen = 5 [*4 = 20 bytes]
	 * 	ip4:            diffs = 0x0 (0)
	 * 	ip4:                    0000 00..  = [0] reserved bit: not set
	 * 	ip4:                    .... ..0.  = [0] ECN bit: ECN capable transport: no
	 * 	ip4:                    .... ...0  = [0] ECE bit: ECE-CE: no
	 * 	ip4:           length = 440
	 * 	ip4:            flags = 0x2 (2)
	 * 	ip4:                    0..  = [0] reserved bit: not set
	 * 	ip4:                    .1.  = [1] don't fragment: set
	 * 	ip4:                    ..0  = [0] more fragments: not set
	 * 	ip4:               id = 0xCB91 (52113)
	 * 	ip4:           offset = 0
	 * 	ip4:     time to live = 254 router hops
	 * 	ip4:         protocol = 17 [udp - unreliable datagram protocol]
	 * 	ip4:  header checksum = 0x8724 (34596)
	 * 	ip4:           source = 131.151.1.59
	 * 	ip4:      destination = 131.151.32.21
	 * 	ip4: 
	 * 	udp:  ******* udp (udp) offset=62 length=8
	 * 	udp: 
	 * 	udp:           source = 7003
	 * 	udp:      destination = 1792
	 * 	udp:           length = 420
	 * 	udp:         checksum = 44574
	 * 	udp: 
	 * 	payload:  ******* payload (data) offset=70 length=412
	 * 	payload: 
	 * 	payload: 0046: 382b3948 e09dbee8 00000001 00000001   8  +  9  H  \e0\9d\be\e8\0 \0 \0 \1 \0 \0 \0 \1 
	 * 	payload: 0056: 00000002 01060000 00000034 00000072   \0 \0 \0 \2 \1 \6 \0 \0 \0 \0 \0 4  \0 \0 \0 r  
	 * 	[truncated...]
	 * </pre>
	 */
	public void testIcmpDestUnreachable() {
		// Wireshark packet # 29 (1-based)
		PcapPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 29 - 1);

		System.out.println(packet.toHexdump(128, false, false, true));
		System.out.println(packet.getState().toDebugString());

		Ip4 ip = new Ip4();
		Icmp icmp = new Icmp(); // Need an instance so we can check on sub header
		Icmp.DestinationUnreachable unreach = new Icmp.DestinationUnreachable();

		assertTrue(packet.hasHeader(Ethernet.ID));
		assertTrue(packet.hasHeader(JProtocol.IP4_ID, 0));
		assertTrue(packet.hasHeader(icmp));
		assertTrue(icmp.hasSubHeader(IcmpType.DESTINATION_UNREACHABLE.getId()));
		assertTrue(icmp.hasSubHeader(unreach));
		assertTrue(packet.hasHeader(ip, 1));
		assertTrue(packet.hasHeader(Udp.ID));
		assertTrue(packet.hasHeader(Payload.ID));

		// Check specific values
		assertEquals(3, icmp.type());
		assertEquals(3, icmp.code());
		assertEquals(0x2731, icmp.checksum());
		assertEquals(0, unreach.reserved());

		assertEquals(0x8724, ip.checksum());
		assertEquals(440, ip.length());

		// Devil's advocate
		assertFalse(icmp.hasSubHeader(IcmpType.ECHO_REPLY.getId()));
		assertFalse(icmp.hasSubHeader(IcmpType.PARAM_PROBLEM.getId()));

	}

	/**
	 * Packet dump:
	 * 
	 * <pre>
	 * Ethernet:  ******* Ethernet (Eth) offset=0 length=14
	 * 	Ethernet: 
	 * 	Ethernet:      destination = 16-03-78-01-16-03
	 * 	Ethernet:           source = 00-E0-F9-CC-18-00
	 * 	Ethernet:         protocol = 0x8100 (33024) [vlan - IEEE 802.1q]
	 * 	Ethernet: 
	 * 	802.1q:  ******* 802.1q (vlan) offset=14 length=4
	 * 	802.1q: 
	 * 	802.1q:         priority = 0
	 * 	802.1q:              cfi = 0
	 * 	802.1q:               id = 32
	 * 	802.1q:             type = 0x800 (2048)
	 * 	802.1q: 
	 * 	ip4:  ******* ip4 (ip) offset=18 length=20
	 * 	ip4: 
	 * 	ip4:          version = 4
	 * 	ip4:             hlen = 5 [*4 = 20 bytes]
	 * 	ip4:            diffs = 0x0 (0)
	 * 	ip4:                    0000 00..  = [0] reserved bit: not set
	 * 	ip4:                    .... ..0.  = [0] ECN bit: ECN capable transport: no
	 * 	ip4:                    .... ...0  = [0] ECE bit: ECE-CE: no
	 * 	ip4:           length = 1497
	 * 	ip4:            flags = 0x0 (0)
	 * 	ip4:                    0..  = [0] reserved bit: not set
	 * 	ip4:                    .0.  = [0] don't fragment: not set
	 * 	ip4:                    ..0  = [0] more fragments: not set
	 * 	ip4:               id = 0x4363 (17251)
	 * 	ip4:           offset = 0
	 * 	ip4:     time to live = 63 router hops
	 * 	ip4:         protocol = 1 [icmp - internet message control protocol]
	 * 	ip4:  header checksum = 0x467 (1127)
	 * 	ip4:           source = 131.151.6.171
	 * 	ip4:      destination = 131.151.32.129
	 * 	ip4: 
	 * 	icmp:  ******* icmp (icmp) offset=38 length=1477
	 * 	icmp: 
	 * 	icmp:             type = 8 [echo request]
	 * 	icmp:             code = 0
	 * 	icmp:         checksum = 0x10FD (4349)
	 * 	icmp: 
	 * 	icmp: + EchoRequest: offset=4 length=1473
	 * 	icmp:               id = 464
	 * 	icmp:         sequence = 7809
	 * 	icmp:      data length = (1469 bytes)
	 * 	icmp: 0004: 742f2338 42a50200 08090a0b 0c0d0e0f   t  /  #  8  B  \a5\2 \0 \b \t \n \v \f \r \e \f 
	 * 	icmp: 0014: 10111213 14151617 18191a1b 1c1d1e1f   \10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e  
	 * 
	 * </pre>
	 */
	public void testIcmpEchoRequest() {
		// Wireshark packet # 58 (1-based)
		PcapPacket packet = TestUtils.getPcapPacket("tests/test-vlan.pcap", 58 - 1);

		System.out.println(packet.toString());

		Icmp icmp = new Icmp(); // Need an instance so we can check on sub header
		Icmp.EchoRequest echo = new Icmp.EchoRequest();

		assertTrue(packet.hasHeader(Ethernet.ID));
		assertTrue(packet.hasHeader(IEEE802dot1q.ID, 0));
		assertTrue(packet.hasHeader(Ip4.ID));
		assertTrue(packet.hasHeader(icmp));
		assertTrue(icmp.hasSubHeader(echo));

		assertEquals(8, icmp.type());
		assertEquals(0, icmp.code());
		assertEquals(0x10FD, icmp.checksum());

		assertEquals(0xd001, echo.id());
		assertEquals(0x811e, echo.sequence());

		// Devil's advocate
		assertFalse(icmp.hasSubHeader(IcmpType.ECHO_REPLY.id));
		assertFalse(icmp.hasSubHeader(IcmpType.PARAM_PROBLEM.id));

	}

	/**
	 * Packet dump:
	 * 
	 * <pre>
	 * Ethernet:  ******* Ethernet (Eth) offset=0 length=14
	 * 	Ethernet: 
	 * 	Ethernet:      destination = 16-03-78-01-16-03
	 * 	Ethernet:           source = 00-40-05-40-EF-24
	 * 	Ethernet:         protocol = 0x8100 (33024) [vlan - IEEE 802.1q]
	 * 	Ethernet: 
	 * 	802.1q:  ******* 802.1q (vlan) offset=14 length=4
	 * 	802.1q: 
	 * 	802.1q:         priority = 0
	 * 	802.1q:              cfi = 0
	 * 	802.1q:               id = 6
	 * 	802.1q:             type = 0x800 (2048)
	 * 	802.1q: 
	 * 	ip4:  ******* ip4 (ip) offset=18 length=20
	 * 	ip4: 
	 * 	ip4:          version = 4
	 * 	ip4:             hlen = 5 [*4 = 20 bytes]
	 * 	ip4:            diffs = 0x0 (0)
	 * 	ip4:                    0000 00..  = [0] reserved bit: not set
	 * 	ip4:                    .... ..0.  = [0] ECN bit: ECN capable transport: no
	 * 	ip4:                    .... ...0  = [0] ECE bit: ECE-CE: no
	 * 	ip4:           length = 1497
	 * 	ip4:            flags = 0x0 (0)
	 * 	ip4:                    0..  = [0] reserved bit: not set
	 * 	ip4:                    .0.  = [0] don't fragment: not set
	 * 	ip4:                    ..0  = [0] more fragments: not set
	 * 	ip4:               id = 0x3B65 (15205)
	 * 	ip4:           offset = 0
	 * 	ip4:     time to live = 255 router hops
	 * 	ip4:         protocol = 1 [icmp - internet message control protocol]
	 * 	ip4:  header checksum = 0x4C64 (19556)
	 * 	ip4:           source = 131.151.32.129
	 * 	ip4:      destination = 131.151.6.171
	 * 	ip4: 
	 * 	icmp:  ******* icmp (icmp) offset=38 length=1477
	 * 	icmp: 
	 * 	icmp:             type = 0 [echo reply]
	 * 	icmp:             code = 0
	 * 	icmp:         checksum = 0x18FD (6397)
	 * 	icmp: 
	 * 	icmp: + EchoReply: offset=4 length=1473
	 * 	icmp:               id = 464
	 * 	icmp:         sequence = 7809
	 * 	icmp:      data length = (1469 bytes)
	 * 	icmp: 0004: 742f2338 42a50200 08090a0b 0c0d0e0f   t  /  #  8  B  \a5\2 \0 \b \t \n \v \f \r \e \f 
	 * 	icmp: 0014: 10111213 14151617 18191a1b 1c1d1e1f   \10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e  
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testIcmpEchoReply() throws IOException {
		// Wireshark packet # 59 (1-based)
		PcapPacket packet = TestUtils.getPcapPacket("tests/test-vlan.pcap", 59 - 1);

//		System.out.println(packet.toString());

		Icmp icmp = new Icmp(); // Need an instance so we can check on sub header
		Icmp.EchoReply echo = new Icmp.EchoReply();

		assertTrue(packet.hasHeader(Ethernet.ID));
		assertTrue(packet.hasHeader(IEEE802dot1q.ID, 0));
		assertTrue(packet.hasHeader(Ip4.ID));
		assertTrue(packet.hasHeader(icmp));
		assertTrue(icmp.hasSubHeader(echo));

		@SuppressWarnings("unused")
    TextFormatter out = new TextFormatter();
//		out.format(echo, Detail.MULTI_LINE_FULL_DETAIL);

		assertEquals(0, icmp.type());
		assertEquals(0, icmp.code());
		assertEquals(0x18FD, icmp.checksum());

		assertEquals(0xd001, echo.id());
		assertEquals(0x811e, echo.sequence());

		// Devil's advocate
		assertTrue(icmp.hasSubHeader(IcmpType.ECHO_REPLY.id));
		assertFalse(icmp.hasSubHeader(IcmpType.ECHO_REQUEST.id));
		assertFalse(icmp.hasSubHeader(IcmpType.PARAM_PROBLEM.id));

	}

}
