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

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.lan.Ethernet;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestIpv6
    extends TestCase {
	
	/** The Constant OUT. */
//	private final static Appendable OUT = TestUtils.DEV_NULL;
	private final static Appendable OUT = System.out;

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
	 * Printing to DEV_NULL still causes entire packet structure to be decoded and
	 * dumped to /dev/null while using every available header found in the packet.
	 * Good stress test for Ip6 based packets.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testScanIpv6File() throws IOException {
		TextFormatter out = new TextFormatter(OUT);
		out.setResolveAddresses(false);

		int i = 0;
		Ethernet eth = new Ethernet();
		for (PcapPacket packet : TestUtils.getIterable("tests/test-ipv6.pcap")) {

			System.out.println(packet.toDebugString());
			if (packet.hasHeader(eth)) {
				out.format(eth);
			}

			out.setFrameIndex(i++);
			out.format(packet);
		}
	}

}
