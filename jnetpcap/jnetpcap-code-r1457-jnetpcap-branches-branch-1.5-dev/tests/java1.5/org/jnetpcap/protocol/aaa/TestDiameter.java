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
package org.jnetpcap.protocol.aaa;

import junit.framework.TestCase;

import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class TestDiameter
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
	 * Test diameter header.
	 */
	public void testDiameterHeader() {
		Diameter diameter = new Diameter(); // Need an instance so we can check on sub header
		// Wireshark packet # 29 (1-based)
		PcapPacket packet = TestUtils.getPcapPacket("tests/tc_TC_IDPRE_EXT0140.pcap", 43 - 1);

		System.out.println(packet.toHexdump(128, false, false, true));

		long map = packet.getState().get64BitHeaderMap(JProtocol.idToGroup(Diameter.ID));
		
		JRegistry.addBindings(Diameter.class);
		System.out.println(JRegistry.toDebugString());
		System.out.println(packet);
		
		assertEquals(JRegistry.lookupId(Diameter.class), Diameter.ID);

		assertTrue(packet.hasHeader(Ethernet.ID));
		assertTrue(packet.hasHeader(JProtocol.IP4_ID, 0));
		assertTrue(packet.hasHeader(diameter));
		
		System.out.println(diameter.toHexdump());

		// Check specific values
		assertEquals(1, diameter.getVersion());
		assertEquals(364, diameter.getMessageLength());
		assertEquals(0x40, diameter.getCommandFlags());
		assertEquals(0x132, diameter.getCommandCode());
	}


}
