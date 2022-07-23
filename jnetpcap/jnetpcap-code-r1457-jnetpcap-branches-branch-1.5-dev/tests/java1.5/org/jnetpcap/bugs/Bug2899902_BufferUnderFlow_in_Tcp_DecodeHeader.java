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

import junit.framework.TestCase;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * User reports the following problem:
 * 
 * <pre>
 * java.lang.NullPointerException
 * at org.jnetpcap.packet.JPacket.getHeader(JPacket.java:660)
 * at org.jnetpcap.packet.JPacket.getHeader(JPacket.java:640)
 * at java.lang.Thread.run(Thread.java:619)
 * PACKET DEBUG
 * ------------
 * JMemory: JMemory@7f3f300e1294class org.jnetpcap.packet.PcapPacket: size=78 bytes
 * JMemory: owner=nio.JMemoryPool$Block.class(size=10240/offset=6468)
 * ------------
 * PACKET DUMP
 * 0000:*00 0a 8a 27 b8 80 00 30 48 32 72 86 08 00*45 00 ...'...0H2r...E.
 * 0010: 00 40 d8 d5 40 00 40 06 2f 80 55 5e 40 14 c3 1d .@..@.@./.U&circ;@...
 * 0020: d9 d2*00 6e 06 86 c4 53 d9 dd 7c e1 ce 2c 50 18 ...n...S..|..,P.
 * 0030: 16 d0 73 4b 00 00*2b 4f 4b 20 50 61 73 73 77 6f ..sK..+OK Passwo
 * 0040: 72 64 20 72 65 71 75 69 72 65 64 2e 0d 0a* rd required...
 * 
 * ------------
 * 
 * java.nio.BufferUnderflowException
 * at org.jnetpcap.nio.JBuffer.getUShort(Native Method)
 * at org.jnetpcap.protocol.network.Ip4.id(Ip4.java:1699)
 * at org.jnetpcap.protocol.network.Ip4.decodeHeader(Ip4.java:1530)
 * at org.jnetpcap.packet.JHeader.decode(JHeader.java:530)
 * at org.jnetpcap.packet.JPacket.getHeaderByIndex(JPacket.java:690)
 * at org.jnetpcap.packet.JPacket.hasHeader(JPacket.java:913)
 * at org.jnetpcap.packet.JPacket.hasHeader(JPacket.java:887)
 * at org.jnetpcap.protocol.tcpip.Tcp.decodeHeader(Tcp.java:185)
 * at org.jnetpcap.packet.JHeader.decode(JHeader.java:530)
 * at org.jnetpcap.packet.JPacket.getHeaderByIndex(JPacket.java:690)
 * at org.jnetpcap.packet.JPacket.hasHeader(JPacket.java:913)
 * at org.jnetpcap.packet.JPacket.hasHeader(JPacket.java:887)
 * 
 * also from the stack trace file java generates when application crashes...
 * 
 * Instructions: (pc=0x00007fbfa1ae67fd)
 * 0x00007fbfa1ae67ed: 55 48 89 e5 48 83 ec 20 48 89 7d e8 48 8b 45 e8
 * 0x00007fbfa1ae67fd: 48 8b 40 38 48 89 c2 48 8b 45 e8 8b 40 4c 48 98
 * 
 * Stack: [0x0000000042085000,0x0000000042186000], sp=0x00000000421842e0, free space=1020k
 * Native frames: (J=compiled Java code, j=interpreted, Vv=VM code, C=native code)
 * C [libjnetpcap.so.1.3.b0011+0x1b7fd] _Z13scan_ethernetP6scan_t+0x10
 * C [libjnetpcap.so.1.3.b0011+0x1d10e] Java_org_jnetpcap_packet_JHeaderScanner_nativeScan+0x4e
 * J org.jnetpcap.packet.JHeaderScanner.nativeScan(Lorg/jnetpcap/packet/JScan;)V
 * 
 * Java frames: (J=compiled Java code, j=interpreted, Vv=VM code)
 * J org.jnetpcap.packet.JHeaderScanner.nativeScan(Lorg/jnetpcap/packet/JScan;)V
 * J org.jnetpcap.packet.JHeaderScanner.scanHeader(Lorg/jnetpcap/packet/JScan;)V
 * v &tilde;StubRoutines::call_stub
 * J org.jnetpcap.packet.JScanner.scan(Lorg/jnetpcap/packet/JPacket;Lorg/jnetpcap/packet/JPacket$State;II)I
 * 
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Bug2899902_BufferUnderFlow_in_Tcp_DecodeHeader
    extends
    TestCase {

	/**
	 * Try and duplicate the bug
	 */
	public void testBug2899902() {

		String packetData =
		    "00 0a 8a 27 b8 80 00 30 48 32 72 86 08 00 45 00 "
		        + "00 40 d8 d5 40 00 40 06 2f 80 55 5e 40 14 c3 1d "
		        + "d9 d2 00 6e 06 86 c4 53 d9 dd 7c e1 ce 2c 50 18 "
		        + "16 d0 73 4b 00 00 2b 4f 4b 20 50 61 73 73 77 6f "
		        + "72 64 20 72 65 71 75 69 72 65 64 2e 0d 0a";
		
		JMemoryPacket p = new JMemoryPacket(JProtocol.ETHERNET_ID, packetData);
		TextFormatter.getDefault().setResolveAddresses(true);
		System.out.println(p);
	}

}
