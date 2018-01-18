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
package org.jnetpcap.protocol.network;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.util.checksum.Checksum;

/**
 * Generic Routing Encapsulation. GRE is a protocol for encapsulation of an
 * arbitrary network layer protocol over another arbitrary network layer
 * protocol.
 * 
 * @author Sly Technologies, Inc.
 * 
 */
@Header(length = 8)
public class GRE extends JHeader implements JHeaderChecksum {

	/** The Constant C_MASK. */
	public static final int C_MASK = 0x01;

	/** The Constant RESERVED_MASK. */
	public static final int RESERVED_MASK = 0x3ffe;

	/** The Constant VERSION_MASK. */
	public static final int VERSION_MASK = 0xe000;

	public static final int GRE_IP_TYPE = 47;

	@Bind(to = Ip4.class)
	public static boolean bindToIp4(JBuffer buffer, Ip4 ip) {
		return ip.type() == GRE_IP_TYPE; // GRE ip.type
	}

	/**
	 * Is checksum present field (C).
	 * 
	 * @return true, if successful
	 */
	@Field(offset = 0, length = 1)
	public boolean c() {
		return (super.getUByte(0) & C_MASK) != 0;
	}

	/**
	 * Sets the is checksum present field (C).
	 * 
	 * @param value
	 *          the value
	 */
	public void c(boolean value) {
		final int b = super.getUByte(0) & ~C_MASK;
		super.setUByte(0, value ? b | 0x01 : b);
	}

	/**
	 * Calculate checksum.
	 * 
	 * @return the int
	 * @see org.jnetpcap.packet.JHeaderChecksum#calculateChecksum()
	 */
	@Override
	public int calculateChecksum() {
		final JPacket packet = getPacket();
		return Checksum.inChecksum(packet, getHeaderOffset(), size()
				- getHeaderOffset());
	}

	/**
	 * Checksum.
	 * 
	 * @return the int
	 * @see org.jnetpcap.packet.JHeaderChecksum#checksum()
	 */
	@Override
	@Field(offset = 32, length = 16, format = "%x")
	public int checksum() {
		return super.getUShort(4);
	}

	/**
	 * Sets a new Checksum.
	 * 
	 * @param value
	 *          the value
	 * @return true, if successful
	 * @see org.jnetpcap.packet.JHeaderChecksum#checksum(int)
	 */
	@Override
	public boolean checksum(int value) {
		c(true); // Set the C flag
		super.setUShort(4, value);

		return true;
	}

	/**
	 * Checksum description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {
		return isChecksumValid() ? "correct" : "incorect, should be "
				+ Long.toHexString(calculateChecksum());
	}

	/**
	 * Checks if is checksum valid.
	 * 
	 * @return true, if is checksum valid
	 * @see org.jnetpcap.packet.JHeaderChecksum#isChecksumValid()
	 */
	@Override
	public boolean isChecksumValid() {
		return !c() || calculateChecksum() == checksum();
	}

	/**
	 * Recalculate checksum.
	 * 
	 * @return true, if successful
	 * @see org.jnetpcap.packet.JHeaderChecksum#recalculateChecksum()
	 */
	@Override
	public boolean recalculateChecksum() {
		c(true);

		return checksum(calculateChecksum());
	}

	/**
	 * Reserved1.
	 * 
	 * @return the int
	 */
	@Field(offset = 1, length = 13)
	public int reserved1() {
		return (super.getUShort(0) & RESERVED_MASK) >> 1;
	}

	/**
	 * Reserved1.
	 * 
	 * @param value
	 *          the value
	 */
	public void reserved1(int value) {
		final int b = super.getUShort(0) & ~RESERVED_MASK;
		super.setUShort(0, b | value << 1);
	}

	/**
	 * Reserved2.
	 * 
	 * @return the int
	 */
	@Field(offset = 48, length = 16)
	public int reserved2() {
		return super.getUShort(12);
	}

	/**
	 * Reserved2.
	 * 
	 * @param value
	 *          the value
	 */
	public void reserved2(int value) {
		super.setUShort(12, value);
	}

	/**
	 * Type.
	 * 
	 * @return the int
	 */
	@Field(offset = 16, length = 16)
	public int type() {
		return super.getUShort(2);
	}

	/**
	 * Type.
	 * 
	 * @param value
	 *          the value
	 */
	public void type(int value) {
		super.setUShort(0, value);
	}

	/**
	 * Version.
	 * 
	 * @return the int
	 */
	@Field(offset = 13, length = 3)
	public int version() {
		return super.getUShort(0) >> 13;
	}

	/**
	 * Version.
	 * 
	 * @param value
	 *          the value
	 */
	public void version(int value) {
		final int b = super.getUShort(0) & ~VERSION_MASK;

		super.setUShort(0, b | value << 13);
	}
}
