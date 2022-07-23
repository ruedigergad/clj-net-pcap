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
package org.jnetpcap.util.checksum;

import org.jnetpcap.nio.JBuffer;

// TODO: Auto-generated Javadoc
/**
 * Main base and utility class that provides native methods for calculating
 * various CRC on buffers.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Checksum {

	/**
	 * Calculate CCITT CRC16 checksum using a CRC32 CCITT seed.
	 * 
	 * @param buffer
	 *            buffer to calculate crc on
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            length within the buffer
	 * @return calculated crc
	 */
	public static native int crc16CCITT(JBuffer buffer, int offset, int length);

	/**
	 * A static read-only buffer that is filled with ZEROs. This buffer is
	 * usefull if you need to perform a calculation that requires a certain
	 * amount of data to be zeroed out. This is common when computing CRC on
	 * packet headers that require the header field that stores the CRC value,
	 * to be zeroed out for the computation on itself.
	 * 
	 * @param buffer
	 *            the buffer
	 * @param offset
	 *            the offset
	 * @param length
	 *            the length
	 * @param crc
	 *            the crc
	 * @return the int
	 */
	// public final static JBuffer ZERO_BUFFER = new JBuffer(new byte[256]);

	/**
	 * Calculate CCITT 16-bit checksum using a partially calculated CRC16.
	 * 
	 * @param buffer
	 *            buffer to calculate crc on
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            length within the buffer
	 * @param crc
	 *            the preload value for the CRC16 computation
	 * @return calculated crc
	 */
	public static int crc16CCITTContinue(JBuffer buffer, int offset,
			int length, int crc) {
		return crc16CCITTSeed(buffer, offset, length, ~crc);
	}

	/**
	 * Calculate CCITT 16-bit checksum using a custom seed.
	 * 
	 * @param buffer
	 *            buffer to calculate crc on
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            length within the buffer
	 * @param seed
	 *            starting seed
	 * @return calculated crc
	 */
	public static native int crc16CCITTSeed(JBuffer buffer, int offset,
			int length, int seed);

	/**
	 * Calculate CCITT CRC16 X.25 checksum using a CCITT seed.
	 * 
	 * @param buffer
	 *            buffer to calculate crc on
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            length within the buffer
	 * @return calculated crc
	 */
	public static native int crc16X25CCITT(JBuffer buffer, int offset,
			int length);

	/**
	 * Calculate a standard CRC32C checksum using a custom seed.
	 * 
	 * @param buffer
	 *            buffer to calculate crc on
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            length within the buffer
	 * @param crc
	 *            the preload value for the CRC32C computation
	 * @return calculated crc
	 */
	public static native int crc32c(JBuffer buffer, int offset, int length,
			int crc);

	/**
	 * Calculate CCITT CRC32 checksum using a CRC32 CCITT seed.
	 * 
	 * @param buffer
	 *            buffer to calculate crc on
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            length within the buffer
	 * @return calculated crc
	 */
	public static native long crc32CCITT(JBuffer buffer, int offset, int length);

	/**
	 * Calculate a standard CRC32C checksum using a partially calculated CRC32.
	 * 
	 * @param buffer
	 *            buffer to calculate crc on
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            length within the buffer
	 * @param crc
	 *            the preload value for the CRC32 computation
	 * @return calculated crc
	 */
	public static int crc32CCITTContinue(JBuffer buffer, int offset,
			int length, int crc) {
		return crc32CCITTSeed(buffer, offset, length, ~crc);
	}

	/**
	 * Calculate CCITT CRC32 checksum using a custom seed.
	 * 
	 * @param buffer
	 *            buffer to calculate crc on
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            length within the buffer
	 * @param seed
	 *            starting seed
	 * @return calculated crc
	 */
	public static native int crc32CCITTSeed(JBuffer buffer, int offset,
			int length, int seed);

	/**
	 * Calculates IEEE 802 based checksums including ethernet/802.3.
	 * 
	 * @param buffer
	 *            buffer to calculate for
	 * @param offset
	 *            offset into the buffer in bytes
	 * @param length
	 *            number of bytes to run calculation on
	 * @return calculated checksum
	 */
	public static native int crc32IEEE802(JBuffer buffer, int offset, int length);

	/**
	 * Flips the bytes from LITTLE to BIG ENDIAN. For example 0x01020304 becomes
	 * 0x04030201.
	 * 
	 * @param c
	 *            source value
	 * @return converted value
	 */
	public static long flip(long c) {
		return ((c >> 0 & 0xFF) << 24) | ((c >> 8 & 0xFF) << 16)
				| ((c >> 16 & 0xFF) << 8) | ((c >> 24 & 0xFF) << 0);
	}

	/**
	 * Icmp.
	 * 
	 * @param buffer
	 *            the buffer
	 * @param ipOffset
	 *            the ip offset
	 * @param icmpOffset
	 *            the icmp offset
	 * @return the int
	 */
	public static native int icmp(JBuffer buffer, int ipOffset, int icmpOffset);

	/**
	 * Calculate a CRC16 using one's complement of one's complement algorithm.
	 * This method computes the CRC16 on a single buffer chunk.
	 * 
	 * @param buffer
	 *            buffer to reach the chunk of data
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            number of bytes to include in calculation
	 * @return computed CRC16
	 */
	public static native int inChecksum(JBuffer buffer, int offset, int length);

	/**
	 * Computes what the checksum should be based on calculated checksum and the
	 * checksum in the header's checksum field.
	 * 
	 * @param checksum
	 *            checksum within the header's field
	 * @param calculateChecksum
	 *            checksum that was calculated
	 * @return resulting checksum of the combination of the 2
	 */
	public static native int inChecksumShouldBe(int checksum,
			int calculateChecksum);

	/**
	 * Pseudo tcp.
	 * 
	 * @param buffer
	 *            the buffer
	 * @param ipOffset
	 *            the ip offset
	 * @param tcpOffset
	 *            the tcp offset
	 * @return the computed crc
	 */
	public static native int pseudoTcp(JBuffer buffer, int ipOffset,
			int tcpOffset);

	/**
	 * Pseudo udp.
	 * 
	 * @param buffer
	 *            the buffer
	 * @param ipOffset
	 *            the ip offset
	 * @param udpOffset
	 *            the udp offset
	 * @return the computed crc
	 */
	public static native int pseudoUdp(JBuffer buffer, int ipOffset,
			int udpOffset);

	/**
	 * Calculate CRC32c checksum of the SCTP message.
	 * 
	 * @param buffer
	 *            the buffer
	 * @param sctpOffset
	 *            the sctp header offset
	 * @return the computed crc
	 */
	public static native int sctp(JBuffer buffer, int sctpOffset, int length);

}
