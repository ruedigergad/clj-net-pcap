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

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.network.Ip4;



// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestSubHeader
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
	 * Test sub header access.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testSubHeaderAccess() throws IOException {
		Ip4 ip = new Ip4();
		Ip4.Timestamp ts = new Ip4.Timestamp();
		Ip4.LooseSourceRoute lsroute = new Ip4.LooseSourceRoute();
		Ip4.StrictSourceRoute ssroute = new Ip4.StrictSourceRoute();
		Ip4.RecordRoute record = new Ip4.RecordRoute();

		JPacket packet =
		    TestUtils.getPcapPacket("tests/test-icmp-recordroute-opt.pcap", 0);

		JFormatter out = new TextFormatter();
		out.format(packet);
		
		System.out.println(packet.getState().toDebugString());
		
		assertNotNull(packet);
		assertTrue(packet.hasHeader(ip));
		assertTrue(ip.hasSubHeaders());
		assertFalse(ip.hasSubHeader(lsroute));
		assertFalse(ip.hasSubHeader(ssroute));
		assertFalse(ip.hasSubHeader(ts));
		
		assertTrue(ip.hasSubHeader(record));
		assertEquals(9, record.addressCount());
		
		byte[] b = record.address(0);
		assertNotNull(b);
		assertEquals(4, b.length);
		assertEquals(-64, b[0]); // 192 in unsinged int
		assertEquals(-88, b[1]); // 168 in unsigned int
		assertEquals(1, b[2]);   // 1
		assertEquals(13, b[3]);  // 13
		
		assertNotNull(packet);
		assertTrue(packet.hasHeader(ip));
		assertTrue(ip.hasSubHeaders());
		assertFalse(ip.hasSubHeader(lsroute));
		assertFalse(ip.hasSubHeader(ssroute));
		assertFalse(ip.hasSubHeader(ts));
		
		assertTrue(ip.hasSubHeader(record));
		assertEquals(9, record.addressCount());
		
		/*
		 * Now do it a second time without resetting the packet
		 */
		b = record.address(0);
		assertNotNull(b);
		assertEquals(4, b.length);
		assertEquals(-64, b[0]); // 192 in unsinged int
		assertEquals(-88, b[1]); // 168 in unsigned int
		assertEquals(1, b[2]);   // 1
		assertEquals(13, b[3]);  // 13

	}


	/**
	 * Test syntax text.
	 */
	public void testSyntaxText() {
		Ip4 ip = new Ip4();
		Ip4.Timestamp ts = new Ip4.Timestamp();
		Ip4.LooseSourceRoute lsroute = new Ip4.LooseSourceRoute();
		Ip4.StrictSourceRoute ssroute = new Ip4.StrictSourceRoute();
		Ip4.RecordRoute record = new Ip4.RecordRoute();

		JPacket packet =
		    TestUtils.getPcapPacket("tests/test-icmp-recordroute-opt.pcap", 0);

		if (packet.hasHeader(ip) && ip.hasSubHeaders()) {

			if (ip.hasSubHeader(lsroute)) {
				System.out.println("LooseSource");
			}

			if (ip.hasSubHeader(ssroute)) {
				System.out.println("StrictSource");
			}

			if (ip.hasSubHeader(ts)) {
				System.out.println("Timestamp");
			}
			
			if (ip.hasSubHeader(record)) {
				System.out.println("RecordRoute");
			}

		}
	}

	/**
	 * Test1.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void test1() throws IOException {
		JPacket packet =
		    TestUtils.getPcapPacket("tests/test-icmp-recordroute-opt.pcap", 0);
		assertNotNull(packet);

		TextFormatter out = new TextFormatter(System.out);
		out.format(packet);

		System.out.println(packet.toString());

		System.out.println(packet.getState().toHexdump());
		System.out.println(packet.getState().toDebugString());
	}

}
