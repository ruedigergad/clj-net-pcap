/**
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

import junit.framework.TestCase;

import org.jnetpcap.protocol.lan.Ethernet;

/**
 * @author Sly Technologies, Inc.
 * 
 */
public class TestJPacketIterator extends TestCase {

	public void testIterable() {
		JPacket packet =
				new JMemoryPacket(Ethernet.ID, VariousInMemoryPackets.PACKET_2);

		for (JHeader header : packet) {
			System.out.println(header);
		}
		System.out.println(packet.getState().toDebugString());

		for (JHeaderChecksum crc : packet.filterByType(JHeaderChecksum.class)) {
			crc.recalculateChecksum();
		}
	}
}
