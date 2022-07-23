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

import org.jnetpcap.packet.format.FormatUtils;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class VariousInMemoryPackets {

	/**
	 * <pre>
	 * Ethernet:  ******* Ethernet (Eth) offset=0 length=14
	 * 	Ethernet: 
	 * 	Ethernet:      destination = 00-07-E9-14-78-A2
	 * 	Ethernet:           source = 00-10-7B-81-24-45
	 * 	Ethernet:         protocol = 0x800 (2048)
	 * 	Ethernet: 
	 * 	ip4:  ******* ip4 (ip) offset=14 length=20
	 * 	ip4: 
	 * 	ip4:          version = 4
	 * 	ip4:             hlen = 5 [*4 = 20 bytes]
	 * 	ip4:            diffs = 0xC0 (192)
	 * 	ip4:                    1100 00..  = [48] reserved bit: code point 48
	 * 	ip4:                    .... ..0.  = [0] ECN bit: ECN capable transport: no
	 * 	ip4:                    .... ...0  = [0] ECE bit: ECE-CE: no
	 * 	ip4:           length = 40
	 * 	ip4:            flags = 0x0 (0)
	 * 	ip4:                    0..  = [0] reserved bit: not set
	 * 	ip4:                    .0.  = [0] don't fragment: not set
	 * 	ip4:                    ..0  = [0] more fragments: not set
	 * 	ip4:               id = 0x5 (5)
	 * 	ip4:           offset = 0
	 * 	ip4:     time to live = 255 router hops
	 * 	ip4:         protocol = 17
	 * 	ip4:  header checksum = 0x70E7 (28903)
	 * 	ip4:           source = 192.168.98.222
	 * 	ip4:      destination = 192.168.101.233
	 * 	ip4: 
	 * 	udp:  ******* udp (udp) offset=34 length=8
	 * 	udp: 
	 * 	udp:           source = 1701
	 * 	udp:      destination = 1701
	 * 	udp:           length = 20
	 * 	udp:         checksum = 57418
	 * 	udp: 
	 * 	l2tp:  ******* l2tp (l2tp) offset=42 length=12
	 * 	l2tp: 
	 * 	l2tp:            flags = 0xC802 (51202)
	 * 	l2tp:                    1... .... .... ....  = [1] type bit: control message
	 * 	l2tp:                    .1.. .... .... ....  = [1] length bit: length field is present
	 * 	l2tp:                    .... 1... .... ....  = [1] sequence bit: Ns and Nr fields are present
	 * 	l2tp:                    .... ..0. .... ....  = [0] offset bit: offset size field is not present
	 * 	l2tp:                    .... ...0 .... ....  = [0] priority bit: no priority
	 * 	l2tp:                    .... .... .... 0010  = [2] version: version is 2
	 * 	l2tp:          version = 2
	 * 	l2tp:           length = 12
	 * 	l2tp:         tunnelId = 2
	 * 	l2tp:        sessionId = 0
	 * 	l2tp:               ns = 2
	 * 	l2tp:               nr = 6
	 * 	l2tp: 
	 * 	payload:  ******* payload (data) offset=54 length=10
	 * 	payload: 
	 * 	payload: 0036: 00000000 00000000 0000                \0 \0 \0 \0 \0 \0 \0 \0 \0 \0       
	 * 	payload: 
	 * </pre>
	 */
	public final static byte[] PACKET_1 =
	    FormatUtils.toByteArray("" + "0007e914 78a20010 7b812445 080045c0"
	        + "00280005 0000ff11 70e7c0a8 62dec0a8"
	        + "65e906a5 06a50014 e04ac802 000c0002"
	        + "00000002 00060000 00000000");

	/**
	 * Same packet as PACKET_1 but DL changed to 802.3/LLC/SNAP
	 * 
	 * <pre>
	 * Frame:
	 * 	Frame:          number = 0
	 * 	Frame:       timestamp = 2009-12-08 01:28:57.392
	 * 	Frame:     wire length = 68 bytes
	 * 	Frame: captured length = 68 bytes
	 * 	Frame:
	 * 	IEEE802dot3:  ******* IEEE802dot3 - &quot;Token ring&quot; - offset=0 (0x0) length=14 
	 * 	IEEE802dot3: 
	 * 	IEEE802dot3:      destination = 0:7:e9:14:78:a2
	 * 	IEEE802dot3:           source = 0:10:7b:81:24:45
	 * 	IEEE802dot3:           length = 72
	 * 	IEEE802dot3: 
	 * 	llc:  ******* IEEE802dot2 offset=14 (0xE) length=3 
	 * 	llc: 
	 * 	llc:             dsap = 0xAA (170)
	 * 	llc:          control = 0x3 (3)
	 * 	llc:             ssap = 0xAA (170)
	 * 	llc: 
	 * 	snap:  ******* IEEESnap offset=17 (0x11) length=5 
	 * 	snap: 
	 * 	snap:              oui = 0x8 (8)
	 * 	snap:              pid = 0x800 (2048) [ip version 4]
	 * 	snap: 
	 * 	Ip:  ******* Ip4 - &quot;ip version 4&quot; - offset=22 (0x16) length=20 protocol suite=NETWORK
	 * 	Ip: 
	 * 	Ip:          version = 4
	 * 	Ip:             hlen = 5 [5 * 4 = 20 bytes, No Ip Options]
	 * 	Ip:         diffserv = 0xC0 (192)
	 * 	Ip:                    1100 00.. = [48] code point: code point 48
	 * 	Ip:                    .... ..0. = [0] ECN bit: not set
	 * 	Ip:                    .... ...0 = [0] ECE bit: not set
	 * 	Ip:           length = 40
	 * 	Ip:               id = 0x5 (5)
	 * 	Ip:            flags = 0x0 (0)
	 * 	Ip:                    0.. = [0] reserved
	 * 	Ip:                    .0. = [0] DF: do not fragment: not set
	 * 	Ip:                    ..0 = [0] MF: more fragments: not set
	 * 	Ip:           offset = 0
	 * 	Ip:              ttl = 255 [time to live]
	 * 	Ip:             type = 17 [next: User Datagram]
	 * 	Ip:         checksum = 0x70E7 (28903) [correct]
	 * 	Ip:           source = 192.168.98.222
	 * 	Ip:      destination = 192.168.101.233
	 * 	Ip: 
	 * 	Udp:  ******* Udp offset=42 (0x2A) length=8 
	 * 	Udp: 
	 * 	Udp:           source = 1701
	 * 	Udp:      destination = 1701
	 * 	Udp:           length = 20
	 * 	Udp:         checksum = 0xE04A (57418) [correct]
	 * 	Udp: 
	 * 	L2TP:  ******* L2TP offset=50 (0x32) length=12 
	 * 	L2TP: 
	 * 	L2TP:            flags = 0xC800 (51200)
	 * 	L2TP:          version = 2
	 * 	L2TP:           length = 12
	 * 	L2TP:              pad = 12
	 * 	L2TP:         tunnelId = 2
	 * 	L2TP:               ns = 2
	 * 	L2TP:        sessionId = 0
	 * 	L2TP:               nr = 6
	 * 	L2TP: 
	 * 	Data:  ******* Payload offset=62 (0x3E) length=6 
	 * 	Data: 
	 * 	003e: 00 00 00 00  00 00                                    ......          
	 * 
	 * 
	 * </pre>
	 */
	public final static byte[] PACKET_2 =
	    FormatUtils.toByteArray(""
	        + "0007e914 78a20010 7b812445 0044" // 802.3 (len= frame)
	        + "aaaa03" // LLC
	        + "000000 0800" // SNAP
	        + "45c0" // IP4
	        + "00280005 0000ff11 70e7c0a8 62dec0a8"
	        + "65e906a5 06a50014 e04ac802 000c0002"
	        + "00000002 00060000 00000000");

	/**
	 * Same as PACKET_2 but ethernet trailer containing FCS
	 * 
	 * <pre>
	 *  JPacket.State#000:      pkt_wirelen=77
	 * 	JPacket.State#000[0]: [id=6  802DOT3    flags=0x801 pre=0 hdr_offset=0    hdr_length=14  gap=0 pay=54  post=9]
	 * 	JPacket.State#000[1]: [id=7  802DOT2    flags=0x800 pre=0 hdr_offset=14   hdr_length=3   gap=0 pay=51  post=0]
	 * 	JPacket.State#000[2]: [id=8  SNAP       flags=0x800 pre=0 hdr_offset=17   hdr_length=5   gap=0 pay=46  post=0]
	 * 	JPacket.State#000[3]: [id=2  IP4        flags=0x800 pre=0 hdr_offset=22   hdr_length=20  gap=0 pay=20  post=0]
	 * 	JPacket.State#000[4]: [id=5  UDP        flags=0x800 pre=0 hdr_offset=42   hdr_length=8   gap=0 pay=18  post=0]
	 * 	JPacket.State#000[5]: [id=10 L2TP       flags=0x800 pre=0 hdr_offset=50   hdr_length=12  gap=0 pay=6   post=0]
	 * 	JPacket.State#000[6]: [id=0  PAYLOAD    flags=0x800 pre=0 hdr_offset=62   hdr_length=6   gap=0 pay=0   post=0]
	 * 
	 * </pre>
	 */
	public final static byte[] PACKET_2_TRAILER =
	    FormatUtils.toByteArray(""
	        + "0007e914 78a20010 7b812445 0044" // 802.3 (len = frame + FCS)
	        + "aaaa03" // LLC
	        + "000000 0800" // SNAP
	        + "45c0" // IP4
	        + "00280005 0000ff11 70e7c0a8 62dec0a8"
	        + "65e906a5 06a50014 e04ac802 000c0002"
	        + "00000002 00060000 00000000" + "112233445566778899" // Ethernet FCS
	    );

}
