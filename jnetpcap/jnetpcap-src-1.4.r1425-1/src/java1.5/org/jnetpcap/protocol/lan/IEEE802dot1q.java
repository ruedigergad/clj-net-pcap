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
package org.jnetpcap.protocol.lan;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * IEEE Vlan header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 4, nicname = "vlan")
public class IEEE802dot1q
    extends JHeader {

	/** The Constant ID. */
	public static final int ID = JProtocol.IEEE_802DOT1Q_ID;


	/**
	 * Priority.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, length = 3, format = "%d")
	public int priority() {
		return (getUByte(0) & 0xE0) >> 5;
	}

	/**
	 * Cfi.
	 * 
	 * @return the int
	 */
	@Field(offset = 3, length = 1, format = "%x")
	public int cfi() {
		return (getUByte(0) & 0x10) >> 4;
	}

	/**
	 * Id.
	 * 
	 * @return the int
	 */
	@Field(offset = 4, length = 12, format = "%x")
	public int id() {
		return getUShort(0) & 0x0FFF;
	}
	
	/**
	 * Type description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String typeDescription() {
		return Ethernet.EthernetType.toString(type());
	}

	/**
	 * Type.
	 * 
	 * @return the int
	 */
	@Field(offset = 16, length = 16, format = "%x")
	public int type() {
		return getUShort(2);
	}
}