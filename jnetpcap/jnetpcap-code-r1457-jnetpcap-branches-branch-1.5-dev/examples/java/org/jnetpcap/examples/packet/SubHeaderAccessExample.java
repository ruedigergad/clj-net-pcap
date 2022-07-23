/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.jnetpcap.examples.packet;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class SubHeaderAccessExample {

	/**
	 * Packet dump:
	 * 
	 * <pre>
	 * Ethernet:  ******* Ethernet (Eth) offset=0 length=14
	 * 	Ethernet: 
	 * 	Ethernet:      destination = 16-03-78-01-16-03
	 * 	Ethernet:           source = 00-60-08-9F-B1-F3
	 * 	Ethernet:         protocol = 0x800 (2048) [ip version 4]
	 * 	Ethernet: 
	 * 	ip4:  ******* ip4 (ip) offset=14 length=20
	 * 	ip4: 
	 * 	ip4:          version = 4
	 * 	ip4:             hlen = 5 [*4 = 20 bytes]
	 * 	ip4:            diffs = 0xC0 (192)
	 * 	ip4:                    1100 00..  = [48] reserved bit: code point 48
	 * 	ip4:                    .... ..0.  = [0] ECN bit: ECN capable transport: no
	 * 	ip4:                    .... ...0  = [0] ECE bit: ECE-CE: no
	 * 	ip4:           length = 468
	 * 	ip4:            flags = 0x0 (0)
	 * 	ip4:                    0..  = [0] reserved bit: not set
	 * 	ip4:                    .0.  = [0] don't fragment: not set
	 * 	ip4:                    ..0  = [0] more fragments: not set
	 * 	ip4:               id = 0xE253 (57939)
	 * 	ip4:           offset = 0
	 * 	ip4:     time to live = 255 router hops
	 * 	ip4:         protocol = 1 [icmp - internet message control protocol]
	 * 	ip4:  header checksum = 0xAE96 (44694)
	 * 	ip4:           source = 131.151.32.21
	 * 	ip4:      destination = 131.151.1.59
	 * 	ip4: 
	 * 	icmp:  ******* icmp (icmp) offset=34 length=8
	 * 	icmp: 
	 * 	icmp:             type = 3 [destination unreachable]
	 * 	icmp:             code = 3 [destination port unreachable]
	 * 	icmp:         checksum = 0x2731 (10033)
	 * 	icmp: 
	 * 	icmp: + DestUnreachable: offset=4 length=4
	 * 	icmp:         reserved = 0
	 * 	icmp: 
	 * 	ip4:  ******* ip4 (ip) offset=42 length=20
	 * 	ip4: 
	 * 	ip4:          version = 4
	 * 	ip4:             hlen = 5 [*4 = 20 bytes]
	 * 	ip4:            diffs = 0x0 (0)
	 * 	ip4:                    0000 00..  = [0] reserved bit: not set
	 * 	ip4:                    .... ..0.  = [0] ECN bit: ECN capable transport: no
	 * 	ip4:                    .... ...0  = [0] ECE bit: ECE-CE: no
	 * 	ip4:           length = 440
	 * 	ip4:            flags = 0x2 (2)
	 * 	ip4:                    0..  = [0] reserved bit: not set
	 * 	ip4:                    .1.  = [1] don't fragment: set
	 * 	ip4:                    ..0  = [0] more fragments: not set
	 * 	ip4:               id = 0xCB91 (52113)
	 * 	ip4:           offset = 0
	 * 	ip4:     time to live = 254 router hops
	 * 	ip4:         protocol = 17 [udp - unreliable datagram protocol]
	 * 	ip4:  header checksum = 0x8724 (34596)
	 * 	ip4:           source = 131.151.1.59
	 * 	ip4:      destination = 131.151.32.21
	 * 	ip4: 
	 * 	udp:  ******* udp (udp) offset=62 length=8
	 * 	udp: 
	 * 	udp:           source = 7003
	 * 	udp:      destination = 1792
	 * 	udp:           length = 420
	 * 	udp:         checksum = 44574
	 * 	udp: 
	 * 	payload:  ******* payload (data) offset=70 length=58
	 * 	payload: 
	 * 	payload: 0046: 382b3948 e09dbee8 00000001 00000001   8  +  9  H  \e0\9d\be\e8\0 \0 \0 \1 \0 \0 \0 \1 
	 * 	payload: 0056: 00000002 01060000 00000034 00000072   \0 \0 \0 \2 \1 \6 \0 \0 \0 \0 \0 4  \0 \0 \0 r  
	 * 	payload: 0066: 0000006f 0000006f 00000074 0000002e   \0 \0 \0 o  \0 \0 \0 o  \0 \0 \0 t  \0 \0 \0 .  
	 * 	payload: 0076: 00000063 00000065 0000                \0 \0 \0 c  \0 \0 \0 e  \0 \0       
	 * 	payload: 
	 * 
	 * </pre>
	 * 
	 * @param args
	 *          all args ignored
	 */
	public static void main(String[] args) {

		/***************************************************************************
		 * First, create our packet we will be accessing The decoded packet contents
		 * are provided above in the java type comment
		 **************************************************************************/
		JPacket packet =
		    new JMemoryPacket(Ethernet.ID,
		    /* Data acquired using JMemory.toHexdump */
		    "      16037801 16030060 089fb1f3 080045c0"
		        + "01d4e253 0000ff01 ae968397 20158397"
		        + "013b0303 27310000 00004500 01b8cb91"
		        + "4000fe11 87248397 013b8397 20151b5b"
		        + "070001a4 ae1e382b 3948e09d bee80000"
		        + "00010000 00010000 00020106 00000000"
		        + "00340000 00720000 006f0000 006f0000"
		        + "00740000 002e0000 00630000 00650000");

		/***************************************************************************
		 * Second, we pre allocate ip, icmp and destination unreachable headers that
		 * we will be working with
		 **************************************************************************/
		Ip4 ip = new Ip4();
		Icmp icmp = new Icmp(); // Need an instance so we can check on sub header
		Icmp.DestinationUnreachable unreach = new Icmp.DestinationUnreachable();

		/***************************************************************************
		 * Third, we check if headers exist and access them
		 **************************************************************************/
		if (packet.hasHeader(Ip4.ID)) { // same as hasHeader(Ip4.ID, 0)
			System.out.println("Has atleast one instance of Ip4 header");
		}

		/***************************************************************************
		 * Fourth, to check for sub headers, you need to first check and instantiate
		 * the parent header, in our case its Icmp. Once the first check succeeds
		 * only then the second check for sub header will take place. If both
		 * succeed we enter the if statement. There we access certain fields from
		 * both the parent icmp header and the child unreach header.
		 **************************************************************************/
		if (packet.hasHeader(icmp) && icmp.hasSubHeader(unreach)) {

			System.out.printf("type=%d, code=%d, crc=0x%x reserved=%d\n",
			    icmp.type(), icmp.code(), icmp.checksum(), unreach.reserved());
		}

		/***************************************************************************
		 * Fifth, notice that we are accessing the second instance of the ip4 header
		 * found in this packet. The first instance is number 0 and the second
		 * number 1.
		 **************************************************************************/
		if (packet.hasHeader(ip, 1)) {
			System.out.println("Has a second Ip4 header too");
			System.out.printf("flags=0x%x crc=0x%x\n", ip.flags(), ip.checksum());
		}

		if (packet.hasHeader(Udp.ID)) {
			System.out.println("Has UDP header as well");
		}

		if (packet.hasHeader(Tcp.ID)) {
			System.err
			    .println("Ooops, we should not be finding a TCP header in this packet");
		}
	}
}
