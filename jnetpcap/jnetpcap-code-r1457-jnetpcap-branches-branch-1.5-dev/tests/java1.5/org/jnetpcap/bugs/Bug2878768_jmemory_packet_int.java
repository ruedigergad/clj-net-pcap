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
package org.jnetpcap.bugs;

import java.nio.ByteOrder;

import junit.framework.TestCase;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.checksum.Checksum;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
@SuppressWarnings("unused")
public class Bug2878768_jmemory_packet_int
    extends
    TestCase {

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}
	
	/**
	 * Test1.
	 */
	public void test1() {
		
		JMemoryPacket packet = new JMemoryPacket(64);
		packet.order(ByteOrder.BIG_ENDIAN);
		packet.setUShort(0 + 12, 0x800);
		packet.setUByte(14 + 0, 0x45);
		System.out.println(packet.toHexdump());
		packet.setUByte(14 + 9, 0x11); //UDP
		System.out.println(packet.toHexdump());
		packet.scan(JProtocol.ETHERNET_ID);
		Ethernet eth = packet.getHeader(new Ethernet());
		Ip4 ip = packet.getHeader(new Ip4());
		Udp udp = packet.getHeader(new Udp());
//		udp.transferFrom(getFakeData(1460)); //Generate Random bytes
		eth.destination(new byte[] {(byte) 0xaa, 0x0c, 0x08, 11, 22, 33});
		eth.source(new byte[] {(byte) 0xaa, 0x0c, 0x08, 11, 22, 34});
		ip.flags(0);
		ip.tos(0);
		ip.source(new byte[] {(byte) 192, (byte) 168, 18, (byte) 218});
		ip.setByteArray(16, new byte[] {(byte) 192,(byte) 168, 18, (byte) 219});
		
		ip.checksum(0);
		System.out.printf("crc=0x%X ip.len=%d\n", Checksum.inChecksum(ip, 0, ip.size()), ip.size());
		ip.checksum(Checksum.inChecksum(ip, 0, ip.size()));
		System.out.println(packet.getState().toDebugString());
		
		System.out.printf("crc=0x%X\n", Checksum.inChecksum(ip, 0, ip.size()));
		
		JBuffer b = new JBuffer(4);
		
		b.order(ByteOrder.LITTLE_ENDIAN);
		b.setUInt(0, 0x14010100);	
		System.out.printf("0x%X\n%s", 0x14010100, b.toHexdump());
		
		b.order(ByteOrder.BIG_ENDIAN);
		b.setUInt(0, 0x14010100);	
		System.out.printf("0x%X\n%s", 0x14010100, b.toHexdump());
	}

}
