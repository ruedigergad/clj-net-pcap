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
 * IEEE SNAP header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 5, nicname = "snap")
public class IEEESnap
    extends JHeader {

	/** The Constant ID. */
	public static final int ID = JProtocol.IEEE_SNAP_ID;
	
	/**
	 * Oui.
	 * 
	 * @return the long
	 */
	@Field(offset = 0, length = 24, format = "%x")
	public long oui() {
		return getUInt(0) & 0x00FFFFFF;
	}

	/**
	 * Pid description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String pidDescription() {
		return Ethernet.EthernetType.toString(pid());
	}
	
	/**
	 * Pid.
	 * 
	 * @return the int
	 */
	@Field(offset = 24, length = 16, format = "%x")
	public int pid() {
		return getUShort(3);
	}
}