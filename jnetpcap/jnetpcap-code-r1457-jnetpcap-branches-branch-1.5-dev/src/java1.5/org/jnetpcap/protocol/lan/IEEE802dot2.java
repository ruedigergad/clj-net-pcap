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

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * IEEE LLC2 header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(nicname = "llc")
public class IEEE802dot2
    extends JHeader {

	/** The Constant ID. */
	public static final int ID = JProtocol.IEEE_802DOT2_ID;

	/**
	 * Header length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return ((buffer.getUShort(offset + 2) & 0x3) == 0x3) ? 4 : 5;
	}

	/**
	 * Control.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, format = "%x")
	public int control() {
		/*
		 * This field is either 1 or 2 bytes in length depending on the control bit.
		 */
		int c = getUByte(2);
		if ((c & 0x3) == 0x3) {
			return c;
		} else {
			return getUShort(2);
		}
	}

	/**
	 * Control length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int controlLength() {
		return ((super.getUByte(2) & 0x3) == 0x3) ? 1 * 8 : 2 * 8;
	}

	/**
	 * Dsap.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, length = 8, format = "%x")
	public int dsap() {
		return getUByte(0);
	}

	/**
	 * Ssap.
	 * 
	 * @return the int
	 */
	@Field(offset = 8, length = 8, format = "%x")
	public int ssap() {
		return getUByte(1);
	}
}