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

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.protocol.network.Ip4;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestJHeader
    extends
    TestUtils {

	/**
	 * Test payload getter from header. The packet is exactly 489 bytes long, the
	 * starting offset of payload for IP header is 0x22 (34) bytes into the packet.
	 */
	public void testJPayloadAccessorGetPayload() {
		JPacket packet = TestUtils.getPcapPacket(HTTP, 5);

		JPayloadAccessor ip = packet.getHeader(new Ip4());
		assertNotNull(ip);

		byte[] buffer = ip.getPayload();
		assertEquals(0x00, buffer[0]);
		assertEquals(0x50, buffer[1]);
		assertEquals(0x0d, buffer[487 - 34]);
		assertEquals(0x0a, buffer[488 - 34]);

		assertEquals(489 - 34, buffer.length);
	}


	/**
	 * Test payload getter from header. The packet is exactly 489 bytes long, the
	 * starting offset of payload for IP header is 0x22 (34) bytes into the packet.
	 */
	public void testJPayloadAccessorTransferPayloadToByteArray() {
		JPacket packet = TestUtils.getPcapPacket(HTTP, 5);

		JPayloadAccessor ip = packet.getHeader(new Ip4());
		assertNotNull(ip);

		byte[] buffer = ip.transferPayloadTo(new byte[489 - 34]);
		assertEquals(0x00, buffer[0]);
		assertEquals(0x50, buffer[1]);
		assertEquals(0x0d, buffer[487 - 34]);
		assertEquals(0x0a, buffer[488 - 34]);

		assertEquals(489 - 34, buffer.length);
	}

	/**
	 * Test payload getter from header. The packet is exactly 489 bytes long, the
	 * starting offset of payload for IP header is 0x22 (34) bytes into the packet.
	 */
	public void testJPayloadAccessorPeerPayloadToJBuffer() {
		JPacket packet = TestUtils.getPcapPacket(HTTP, 5);

		JPayloadAccessor ip = packet.getHeader(new Ip4());
		assertNotNull(ip);

		JBuffer buffer = ip.peerPayloadTo(new JBuffer(JMemory.Type.POINTER));
		assertEquals(0x00, buffer.getUByte(0));
		assertEquals(0x50, buffer.getUByte(1));
		assertEquals(0x0d, buffer.getUByte(487 - 34));
		assertEquals(0x0a, buffer.getUByte(488 - 34));

//		System.out.println(buffer.toHexdump());
		assertEquals(489 - 34, buffer.size());
	}

	/**
	 * Test payload getter from header. The packet is exactly 489 bytes long, the
	 * starting offset of payload for IP header is 0x22 (34) bytes into the packet.
	 */
	public void testJPayloadAccessorTransferPayloadToJBuffer() {
		JPacket packet = TestUtils.getPcapPacket(HTTP, 5);

		JPayloadAccessor ip = packet.getHeader(new Ip4());
		assertNotNull(ip);

		JBuffer buffer = ip.transferPayloadTo(new JBuffer(489 - 34));
		assertEquals(0x00, buffer.getUByte(0));
		assertEquals(0x50, buffer.getUByte(1));
		assertEquals(0x0d, buffer.getUByte(487 - 34));
		assertEquals(0x0a, buffer.getUByte(488 - 34));

//		System.out.println(buffer.toHexdump());
		assertEquals(489 - 34, buffer.size());
	}

}
