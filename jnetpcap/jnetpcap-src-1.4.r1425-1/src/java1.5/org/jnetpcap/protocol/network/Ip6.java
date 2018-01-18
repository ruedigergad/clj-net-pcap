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

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * IP version 6 header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 40)
public class Ip6 extends JHeader {

	/** The Constant ID. */
	public static final int ID = JProtocol.IP6_ID;

	/**
	 * Destination.
	 * 
	 * @return the byte[]
	 */
	@Field(offset = 8 * 8, length = 128, format = "#ip6#")
	@FlowKey(index = 0)
	public byte[] destination() {
		return getByteArray(24, 16);
	}

	/**
	 * Destination to byte array.
	 * 
	 * @param address
	 *            the address
	 * @return the byte[]
	 */
	public byte[] destinationToByteArray(byte[] address) {
		if (address.length != 16) {
			throw new IllegalArgumentException("address must be 16 byte long");
		}
		return getByteArray(24, address);
	}

	/**
	 * Converts the 16-byte IP6 address to a 4-byte hash of the value
	 * 
	 * @return 32-bit hash
	 */
	public int destinationToIntHash() {
		int hash = 0;
		for (int i = 0; i < 16; i += 4) {
			hash ^= super.getUInt(i + 24);
		}
		return hash;
	}

	/**
	 * Flow label.
	 * 
	 * @return the int
	 */
	@Field(offset = 12, length = 20)
	public int flowLabel() {
		return getInt(0) & 0x000FFFFF; // We drop the sign bits anyway
	}

	/**
	 * Hop limit.
	 * 
	 * @return the int
	 */
	@Field(offset = 7 * 8, length = 8)
	public int hopLimit() {
		return getUByte(7);
	}

	/**
	 * Length.
	 * 
	 * @return the int
	 */
	@Field(offset = 32, length = 16)
	public int length() {
		return getUShort(4);
	}

	/**
	 * Next.
	 * 
	 * @return the int
	 */
	@Field(offset = 6 * 8, length = 8)
	@FlowKey(index = 1)
	public int next() {
		return getUByte(6);
	}

	/**
	 * Source.
	 * 
	 * @return the byte[]
	 */
	@Field(offset = 8 * 8, length = 128, format = "#ip6#")
	@FlowKey(index = 0)
	public byte[] source() {
		return getByteArray(8, 16);
	}

	/**
	 * Source to byte array.
	 * 
	 * @param address
	 *            the address
	 * @return the byte[]
	 */
	public byte[] sourceToByteArray(byte[] address) {
		if (address.length != 16) {
			throw new IllegalArgumentException("address must be 16 byte long");
		}
		return getByteArray(8, address);
	}

	/**
	 * Converts the 16-byte IP6 address to a 4-byte hash of the value
	 * 
	 * @return 32-bit hash
	 */
	public int sourceToIntHash() {
		int hash = 0;
		for (int i = 0; i < 16; i += 4) {
			hash ^= super.getUInt(i + 8);
		}
		return hash;
	}

	/**
	 * Traffic class.
	 * 
	 * @return the int
	 */
	@Field(offset = 4, length = 8)
	public int trafficClass() {
		return getUShort(0) & 0x0FFF;
	}

	public void trafficClass(int value) {
		int data = getUShort(0);
		value = (value & 0x0F);
		setUShort(0, value);
	}

	/**
	 * Gets the value from the version field
	 * 
	 * @return reads the 4-bit version value
	 */
	@Field(offset = 0, length = 4)
	public int version() {
		return getUByte(0) >> 4;
	}

	/**
	 * Sets the version field value
	 * 
	 * @param 4-bit integer value
	 */
	public void version(int value) {
		int data = getUByte(0) & 0x0F; // Clear upper 4 bits
		data |= (value & 0x0F) << 4; // Set in upper 4 bits
		setUByte(0, data);
	}

}
