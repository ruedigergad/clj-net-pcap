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

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;

// TODO: Auto-generated Javadoc
/**
 * 2832692 hasHeader throws NULL ptr exception. Its not handling an
 * unimplemented Ip4 option.
 * <p>
 * Several JMemoryPacket constructors do not set the required "wirelen" header
 * property. This causes exceptions to be thrown by the quick-scanner.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Bug2832692_null_ptr_in_hasHeader
    extends
    TestUtils {

	/** The Constant BUG_FILE. */
	private final static String BUG_FILE = TestUtils.L2TP;

	/**
	 * SKI p_test read entire suspect file.
	 */
	public void SKIP_testReadEntireSuspectFile() {

		Ip4 ip = new Ip4();
		for (PcapPacket packet : TestUtils.getIterable(BUG_FILE)) {
			try {
				if (packet.getFrameNumber() == 15) {
					System.out.println(packet);
					System.out.println(packet
					    .toHexdump(packet.size(), false, false, true));
				}

				packet.hasHeader(ip);
			} catch (NullPointerException e) {
				System.out.println(packet.getState().toDebugString());
				System.out.println(packet.toHexdump());

				throw e;
			}
		}
	}

	/**
	 * Tests if RouterAlert Ip4 optional header is found and peered properly.
	 * 
	 * <pre>
	 * 	Frame:
	 * 	Frame:          number = 0
	 * 	Frame:       timestamp = 1969-12-31 19:00:00.0
	 * 	Frame:     wire length = 60 bytes
	 * 	Frame: captured length = 0 bytes
	 * 	Frame:
	 * 	Eth:  ******* Ethernet - &quot;Ethernet&quot; - offset=0 (0x0) length=14 
	 * 	Eth: 
	 * 	Eth:      destination = 1:0:5e:0:0:16
	 * 	Eth:                    .... ..0. .... .... = [0] LG bit
	 * 	Eth:                    .... ...0 .... .... = [0] IG bit
	 * 	Eth:           source = 0:3:ff:2a:7a:6c
	 * 	Eth:                    .... ..0. .... .... = [0] LG bit
	 * 	Eth:                    .... ...0 .... .... = [0] IG bit
	 * 	Eth:             type = 0x800 (2048) [ip version 4]
	 * 	Eth: 
	 * 	Ip:  ******* Ip4 - &quot;ip version 4&quot; - offset=14 (0xE) length=24 protocol suite=NETWORK
	 * 	Ip: 
	 * 	Ip:          version = 4
	 * 	Ip:             hlen = 6 [6 * 4 = 24 bytes, Ip Options Present]
	 * 	Ip:         diffserv = 0x0 (0)
	 * 	Ip:                    0000 00.. = [0] code point: not set
	 * 	Ip:                    .... ..0. = [0] ECN bit: not set
	 * 	Ip:                    .... ...0 = [0] ECE bit: not set
	 * 	Ip:           length = 40
	 * 	Ip:               id = 0xD704 (55044)
	 * 	Ip:            flags = 0x0 (0)
	 * 	Ip:                    0.. = [0] reserved
	 * 	Ip:                    .0. = [0] DF: do not fragment: not set
	 * 	Ip:                    ..0 = [0] MF: more fragments: not set
	 * 	Ip:           offset = 0
	 * 	Ip:              ttl = 1 [time to live]
	 * 	Ip:             type = 2 [next: 2]
	 * 	Ip:         checksum = 0xACFA (44282) [correct]
	 * 	Ip:           source = 192.168.0.18
	 * 	Ip:      destination = 224.0.0.22
	 * 	Ip: 
	 * 	Ip: + RouterAlert: offset=20 length=4
	 * 	Ip:             code = 148
	 * 	Ip:                    1... .... = [1] copy: copy to all fragments
	 * 	Ip:                    .00. .... = [0] class: CONTROL
	 * 	Ip:                    ...1 0100 = [20] type: ROUTER_ALERT
	 * 	Ip:           length = 4
	 * 	Ip:           action = 0 [EXAMINE_PACKET]
	 * 	Ip: 
	 * 	Data:  ******* Payload offset=38 (0x26) length=22 
	 * 	Data: 
	 * 	0026: 22 00 ea 03  00 00 00 01  04 00 00 00  ef ff ff fa    &quot;...............
	 * 	0036: 00 00 00 00  00 00                                    ......          
	 * </pre>
	 */
	public void testIp4OptionRouterAlert() {
		String data =
		    " 01 00 5e 00  00 16 00 03  ff 2a 7a 6c  08 00 46 00"
		        + " 00 28 d7 04  00 00 01 02  ac fa c0 a8  00 12 e0 00"
		        + " 00 16 94 04  00 00 22 00  ea 03 00 00  00 01 04 00"
		        + " 00 00 ef ff  ff fa 00 00  00 00 00 00             ";
		JMemoryPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
		Ip4 ip = new Ip4();
		Ip4.RouterAlert alert = new Ip4.RouterAlert();
		
		assertTrue(packet.hasHeader(ip));
		assertTrue(ip.hasSubHeader(alert));

		System.out.println(alert);
	}
}
