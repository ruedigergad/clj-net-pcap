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
package org.jnetpcap.protocol.vpn;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * Layer 2 Tunneling Protocol header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
public class L2TP
    extends JHeader {

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
		int flags = buffer.getUShort(0);
		int len = 6;
		if ((flags & FLAG_L) != 0) {
			len += 2;
		}

		if ((flags & FLAG_S) != 0) {
			len += 4;
		}

		if ((flags & FLAG_O) != 0) {
			len += 4;
		}

		return len;
	}

	/** The Constant FLAG_L. */
	public final static int FLAG_L = 0x4000;

	/** The Constant FLAG_O. */
	public final static int FLAG_O = 0x0200;

	/** The Constant FLAG_P. */
	public final static int FLAG_P = 0x0100;

	/** The Constant FLAG_S. */
	public final static int FLAG_S = 0x0800;

	/** The Constant FLAG_T. */
	public final static int FLAG_T = 0x8000;

	/** The Constant ID. */
	public static final int ID = JProtocol.L2TP_ID;

	/** The Constant MASK_VERSION. */
	public final static int MASK_VERSION = 0x000E;
	
	/** The Constant MASK_FLAGS. */
	public final static int MASK_FLAGS = 0xFFF1;

	/** The off id. */
	private int offId;

	/** The off length. */
	private int offLength;

	/** The off offset. */
	private int offOffset;

	/** The off sequence. */
	private int offSequence;

	/**
	 * Decode header.
	 * 
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	public void decodeHeader() {

		int flags = flags();
		int o = 2;

		if (isSet(flags, FLAG_L)) {
			offLength = 2;
			o += 2;
		} else {
			offLength = 0;
		}
		offId = o;
		o += 4;

		if (isSet(flags, FLAG_S)) {
			offSequence = o;
			o += 4;
		} else {
			offSequence = 0;
		}

		if (isSet(flags, FLAG_O)) {
			offOffset = o;
			o += 4;
		} else {
			offOffset = 0;
		}
	}

	/**
	 * Flags.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, length = 12, format = "%x")
	public int flags() {
		return getUShort(0) & MASK_FLAGS;
	}

	/**
	 * Checks for length.
	 * 
	 * @return true, if successful
	 */
	@Dynamic(Field.Property.CHECK)
	public boolean hasLength() {
		return isSet(flags(), FLAG_L);
	}

	/**
	 * Checks for n.
	 * 
	 * @return true, if successful
	 */
	@Dynamic(Field.Property.CHECK)
	public boolean hasN() {
		return isSet(flags(), FLAG_S);
	}

	/**
	 * Checks for offset.
	 * 
	 * @return true, if successful
	 */
	@Dynamic(Field.Property.CHECK)
	public boolean hasOffset() {
		return isSet(flags(), FLAG_O);
	}

	/**
	 * Checks if is sets the.
	 * 
	 * @param i
	 *          the i
	 * @param m
	 *          the m
	 * @return true, if is sets the
	 */
	private boolean isSet(int i, int m) {
		return (i & m) != 0;
	}
	
	
	/**
	 * Length offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int lengthOffset() {
		return offLength * 8;
	}

	/**
	 * Length.
	 * 
	 * @return the int
	 */
	@Field(length = 16)
	public int length() {
		return getUShort(offLength);
	}
	
	/**
	 * Nr offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int nrOffset() {
		return (offSequence + 2) * 8;
	}

	/**
	 * Nr.
	 * 
	 * @return the int
	 */
	@Field(length = 16)
	public int nr() {
		return getUShort(offSequence + 2);
	}

	/**
	 * Ns offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int nsOffset() {
		return offSequence * 8;
	}
	
	/**
	 * Ns.
	 * 
	 * @return the int
	 */
	@Field(length = 16)
	public int ns() {
		return getUShort(offSequence);
	}

	/**
	 * Offset offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int offsetOffset() {
		return offOffset * 8;
	}
	
	/**
	 * Offset.
	 * 
	 * @return the int
	 */
	@Field(length = 16)
	public int offset() {
		return getUShort(offOffset);
	}

	/**
	 * Pad offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int padOffset() {
		return (offLength + 2) * 8;
	}
	
	/**
	 * Pad.
	 * 
	 * @return the int
	 */
	@Field(length = 16)
	public int pad() {
		return getUShort(offOffset + 2);
	}

	/**
	 * Session id offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int sessionIdOffset() {
		return (offId * 2) * 8;
	}
	
	/**
	 * Session id.
	 * 
	 * @return the int
	 */
	@Field(length = 16)
	public int sessionId() {
		return getUShort(offId + 2);
	}

	/**
	 * Tunnel id offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int tunnelIdOffset() {
		return offId * 8;
	}
	
	/**
	 * Tunnel id.
	 * 
	 * @return the int
	 */
	@Field(length = 16)
	public int tunnelId() {
		return getUShort(offId);
	}

	/**
	 * Version.
	 * 
	 * @return the int
	 */
	@Field(offset = 13, length = 3)
	public int version() {
		return getUShort(0) & MASK_VERSION;
	}
}
