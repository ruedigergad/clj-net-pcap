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
package org.jnetpcap.header;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.protocol.lan.Ethernet;

// TODO: Auto-generated Javadoc
/**
 * A collection of network layer protocol to protocol bindings.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class BindNetworkFamily {

	/**
	 * Bind ip4 to ethernet.
	 * 
	 * @param packet
	 *          the packet
	 * @param eth
	 *          the eth
	 * @return true, if successful
	 */
	@Bind(from = MyHeader.class, to = Ethernet.class, intValue = 0x800)
	public static boolean bindIp4ToEthernet(JPacket packet, Ethernet eth) {
		return (eth.type() == 0x800);
	}

//	@Bind(from = Icmp.class, to = MyHeader.class)
//	public static boolean bindIcmpToIp4(JPacket packet, MyHeader ip) {
//		return ip.checkType(1);
//	}
//
//	@Bind(from = Tcp.class, to = Ip4.class)
//	public static boolean bindTcpToIp4(JPacket packet, Ip4 ip) {
//		return (ip.type() == 6 && ip.offset() == 0);
//	}
//
//	@Bind(from = Payload.class, to = Tcp.class, intValue = 23)
//	public static boolean bindTelnetToTcp(JPacket packet, Tcp tcp) {
//		return (tcp.source() == 23 || tcp.destination() == 23);
//	}
//
//	@Bind(from = Payload.class, to = Tcp.class, intValue = {
//	    80,
//	    8080 })
//	public static boolean bindHttpToTcp(JPacket packet, Tcp tcp) {
//		final int s = tcp.source();
//		final int d = tcp.destination();
//		return s == 80 || d == 80 || s == 8080 || d == 8080;
//	}
//
//	@Bind(from = Payload.class, to = Payload.class, stringValue = {
//	    "text/html*",
//	    "*html*" })
//	public static boolean bindHtmlToHttp(JPacket packet, Tcp tcp) {
//		return (tcp.source() == 0 || tcp.destination() == 0);
//	}
}
