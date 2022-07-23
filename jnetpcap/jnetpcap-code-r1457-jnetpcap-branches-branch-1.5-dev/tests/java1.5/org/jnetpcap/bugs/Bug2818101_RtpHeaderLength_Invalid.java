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

import java.io.IOException;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import junit.framework.TestCase;

// TODO: Auto-generated Javadoc
/**
 * <p>
 * Bug #2818101 - Rtp incorrect header length
 * </p>
 * User reports an exception being thrown during peering:
 * 
 * <pre>
 * Platform: win32/x86
 * Versions: 1.3.b0003 and 1.3.b0004
 * 
 *  JMemory: JMemory@ce18738: size=280 bytes
 * 	JMemory: owner=PcapHeader.class(size=0/offset=16)
 * 	JMemory: references(null)
 * 	JPacket.State#26173: sizeof(packet_state_t)=120
 * 	JPacket.State#26173: sizeof(header_t)=32 and *5=160
 * 	JPacket.State#26173:   pkt_header_map=0x80027
 * 	JPacket.State#26173:        pkt_flags=0x0
 * 	JPacket.State#26173: pkt_header_count=5
 * 	JPacket.State#26173:      pkt_wirelen=138
 * 	JPacket.State#26173[0]: [id=1  ETHERNET   flags=0x0 pre=0 hdr_offset=0    hdr_length=14  gap=0 pay=124 post=0]
 * 	JPacket.State#26173[1]: [id=2  IP4        flags=0x0 pre=0 hdr_offset=14   hdr_length=20  gap=0 pay=104 post=0]
 * 	JPacket.State#26173[2]: [id=5  UDP        flags=0x0 pre=0 hdr_offset=34   hdr_length=8   gap=0 pay=96  post=0]
 * 	JPacket.State#26173[3]: [id=19 RTP        flags=0x0 pre=0 hdr_offset=42   hdr_length=103920 gap=0 pay=-103696 post=65408]
 * 	JPacket.State#26173[4]: [id=0  PAYLOAD    flags=0x0 pre=0 hdr_offset=103962 hdr_length=-103824 gap=0 pay=0   post=0]
 * 
 * 	0000:*00 0c 41 76  33 05 00 03  6b f7 12 0f  08 00*45 00    ..Av3...k.....E.
 * 	0010: 00 7c 6f f7  40 00 fa 11  f8 8f 41 20  01 41 c0 a8    .|o.@.....A .A..
 * 	0020: 14 e0*00 35  c0 66 00 68  60 f0*b4 16  85 83 00 01    ...5.f.h`.......
 * 	0030: 00 00 00 01  00 00 0a 6e  6d 72 66 6c  69 73 6d 73    .......nmrflisms
 * 	0040: 31 04 69 61  67 72 03 6e  65 74 00 00  01 00 01 c0    1.iagr.net......
 * 	0050: 17 00 06 00  01 00 00 2a  30 00 2f 05  70 64 6e 73    .......*0./.pdns
 * 	0060: 31 08 75 6c  74 72 61 64  6e 73 c0 1c  07 6b 67 72    1.ultradns...kgr
 * 	0070: 61 75 65 72  c0 17 77 bf  dd f5 00 00  2a 30 00 00    auer..w.....*0..
 * 	0080: 0e 10 00 27  8d 00 00 01  51 80   
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Bug2818101_RtpHeaderLength_Invalid
    extends
    TestCase {

	/**
	 * Test print each header gradually.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testPrintEachHeaderGradually() throws IOException {

		final String data =
		    "" + "00 0c 41 76  33 05 00 03  6b f7 12 0f  08 00 45 00"
		        + "00 7c 6f f7  40 00 fa 11  f8 8f 41 20  01 41 c0 a8"
		        + "14 e0 00 35  c0 66 00 68  60 f0 b4 16  85 83 00 01"
		        + "00 00 00 01  00 00 0a 6e  6d 72 66 6c  69 73 6d 73"
		        + "31 04 69 61  67 72 03 6e  65 74 00 00  01 00 01 c0"
		        + "17 00 06 00  01 00 00 2a  30 00 2f 05  70 64 6e 73"
		        + "31 08 75 6c  74 72 61 64  6e 73 c0 1c  07 6b 67 72"
		        + "61 75 65 72  c0 17 77 bf  dd f5 00 00  2a 30 00 00"
		        + "0e 10 00 27  8d 00 00 01  51 80" + "";
		final JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, data);

		// final String TEMP_CAP = "tests/temp.pcap";
		// final File TEMP_CAP_FILE = new File(TEMP_CAP);
		// if (TEMP_CAP_FILE.exists()) {
		// TEMP_CAP_FILE.delete();
		// }
		// FormatUtils.createPcapFile(TEMP_CAP, data);

		// System.out.println(packet);
		System.out.println(packet.getHeader(new Ethernet()));
		System.out.println(packet.getHeader(new Ip4()));
		System.out.println(packet.getHeader(new Udp()));
		System.out.println(packet.getState().toDebugString());

	}

}
