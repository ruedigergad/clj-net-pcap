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

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Rip1;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * 
 */
@SuppressWarnings("unused")
public class TestNetwork extends TestUtils {

	/** The Constant RIP_V1. */
	public final static String RIP_V1 = "tests/Rip_V1.pcap";

	/**
	 * Test arp.
	 */
	public void testArp() {
		JPacket packet = super.getPcapPacket(VLAN, 189 - 1);

		assertTrue(packet.hasHeader(JProtocol.ARP_ID));

		Arp arp = new Arp();
		assertTrue(packet.hasHeader(arp));
		assertEquals(Arp.OpCode.REQUEST, arp.operationEnum());
		System.out.println(packet);
	}

	/**
	 * SKI ptest rip1.
	 * 
	 * @throws RegistryHeaderErrors
	 *           the registry header errors
	 */
	public void SKIPtestRip1() throws RegistryHeaderErrors {
		final int RIP1_ID = JRegistry.register(Rip1.class);

		JPacket packet = super.getPcapPacket(RIP_V1, 1 - 1);

		assertTrue(packet.hasHeader(RIP1_ID));

		Rip1 rip = new Rip1();

		System.out.println(packet);

	}

	public void testGRE() {

	}
}
