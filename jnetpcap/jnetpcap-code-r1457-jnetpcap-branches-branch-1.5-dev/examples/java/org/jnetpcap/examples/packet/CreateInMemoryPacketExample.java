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
import org.jnetpcap.protocol.JProtocol;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class CreateInMemoryPacketExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		JPacket packet =
		    new JMemoryPacket(JProtocol.ETHERNET_ID,
		    /* Data acquired using JMemory.toHexdump on a different packet */
		    "      16037801 16030060 089fb1f3 080045c0"
		        + "01d4e253 0000ff01 ae968397 20158397"
		        + "013b0303 27310000 00004500 01b8cb91"
		        + "4000fe11 87248397 013b8397 20151b5b"
		        + "070001a4 ae1e382b 3948e09d bee80000"
		        + "00010000 00010000 00020106 00000000"
		        + "00340000 00720000 006f0000 006f0000"
		        + "00740000 002e0000 00630000 00650000");

		System.out.println(packet.toString());
	}

}
