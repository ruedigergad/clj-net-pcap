/*
 * Copyright (C) 2012 Sly Technologies, Inc.
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
package org.jnetpcap.protocol.sigtran;

import java.nio.ByteOrder;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * Selective Acknowledgement (SACK) (3)
 * <p>
 * This chunk is sent to the peer endpoint to acknowledge received DATA chunks
 * and to inform the peer endpoint of gaps in the received subsequences of DATA
 * chunks as represented by their TSNs.
 * </p>
 * <p>
 * The SACK MUST contain the Cumulative TSN Ack, Advertised Receiver Window
 * Credit (a_rwnd), Number of Gap Ack Blocks, and Number of Duplicate TSNs
 * fields.
 * <p>
 * </p>
 * By definition, the value of the Cumulative TSN Ack parameter is the last TSN
 * received before a break in the sequence of received TSNs occurs; the next TSN
 * value following this one has not yet been received at the endpoint sending
 * the SACK. This parameter therefore acknowledges receipt of all TSNs less than
 * or equal to its value.
 * <p>
 * </p>
 * The handling of a_rwnd by the receiver of the SACK is discussed in detail in
 * RFC 4960 Section 6.2.1.
 * <p>
 * </p>
 * The SACK also contains zero or more Gap Ack Blocks. Each Gap Ack Block
 * acknowledges a subsequence of TSNs received following a break in the sequence
 * of received TSNs. By definition, all TSNs acknowledged by Gap Ack Blocks are
 * greater than the value of the Cumulative TSN Ack.
 * <p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 3    |Chunk  Flags   |      Chunk Length             |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                      Cumulative TSN Ack                       |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |          Advertised Receiver Window Credit (a_rwnd)           |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        | Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = X |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |  Gap Ack Block #1 Start       |   Gap Ack Block #1 End        |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        /                                                               /
 *        \                              ...                              \
 *        /                                                               /
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Gap Ack Block #N Start      |  Gap Ack Block #N End         |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                       Duplicate TSN 1                         |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        /                                                               /
 *        \                              ...                              \
 *        /                                                               /
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                       Duplicate TSN X                         |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Selective Acknowledgement", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-sack")
public class SctpSack extends SctpChunk {
	
	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_SACK_ID;

	/**
	 * Cumulative TSN Ack: 32 bits (unsigned integer)
	 * <p>
	 * This parameter contains the TSN of the last DATA chunk received in
	 * sequence before a gap. In the case where no DATA chunk has been received,
	 * this value is set to the peer's Initial TSN minus one.
	 * </p>
	 * 
	 * @return TSN acks
	 */
	@Field(offset = 4 * BYTE, length = 4 * BYTE, display = "Cumulative TSN Ack")
	public long ack() {
		return super.getUInt(4);
	}

	/**
	 * Cumulative TSN Ack: 32 bits (unsigned integer)
	 * <p>
	 * This parameter contains the TSN of the last DATA chunk received in
	 * sequence before a gap. In the case where no DATA chunk has been received,
	 * this value is set to the peer's Initial TSN minus one.
	 * </p>
	 * 
	 * @param value
	 *            TSN acks
	 */
	public void ack(long value) {
		super.setUInt(4, value);
	}

	/**
	 * Advertised Receiver Window Credit (a_rwnd): 32 bits (unsigned integer)
	 * <p>
	 * This field indicates the updated receive buffer space in bytes of the
	 * sender of this SACK; see RFC 4960 Section 6.2.1 for details.
	 * </p>
	 * 
	 * @return value window credit
	 */
	@Field(offset = 8 * BYTE, length = 4 * BYTE, display = "Advertised Receiver Window Credit")
	public long window() {
		return super.getUInt(8);
	}

	/**
	 * Advertised Receiver Window Credit (a_rwnd): 32 bits (unsigned integer)
	 * <p>
	 * This field indicates the updated receive buffer space in bytes of the
	 * sender of this SACK; see RFC 4960 Section 6.2.1 for details.
	 * </p>
	 * 
	 * @param value
	 *            value window credit
	 */
	public void window(long value) {
		super.setUInt(8, value);
	}

	/**
	 * Number of Gap Ack Blocks: 16 bits (unsigned integer)
	 * <p>
	 * Indicates the number of Gap Ack Blocks included in this SACK.
	 * </p>
	 * 
	 * @return number of ACK blocks
	 */
	@Field(offset = 12 * BYTE, length = 2 * BYTE, display = "Number of Gap Ack Blocks")
	public int gapBlockCount() {
		return super.getUShort(12);
	}

	/**
	 * Number of Gap Ack Blocks: 16 bits (unsigned integer)
	 * <p>
	 * Indicates the number of Gap Ack Blocks included in this SACK.
	 * </p>
	 * 
	 * @param value
	 *            number of ACK blocks
	 */
	public void gapBlockCount(int value) {
		super.setUShort(12, value);
	}

	/**
	 * Number of Duplicate TSNs: 16 bit
	 * <p>
	 * This field contains the number of duplicate TSNs the endpoint has
	 * received. Each duplicate TSN is listed following the Gap Ack Block list.
	 * </p>
	 * 
	 * @return number of duplicate TSNs
	 */
	@Field(offset = 14 * BYTE, length = 2 * BYTE, display = "Number of Duplicate TSNs")
	public int duplicateTSNCount() {
		return super.getUShort(14);
	}

	/**
	 * Number of Duplicate TSNs: 16 bit
	 * <p>
	 * This field contains the number of duplicate TSNs the endpoint has
	 * received. Each duplicate TSN is listed following the Gap Ack Block list.
	 * </p>
	 * 
	 * @param value
	 *            number of duplicate TSNs
	 */
	public void duplicateTSNCount(int value) {
		super.setUShort(14, value);
	}

	/**
	 * Formats table of gap blocks for display
	 * 
	 * @return multi-line table of missing blocks
	 */
	@Field(offset = 20 * BYTE, length = 0, display = "Gap Ack Block", format = "%s[]")
	public String[] printGapBlocks() {
		GapBlock[] gaps = gaps();
		String[] lines = new String[gaps.length];

		for (int i = 0; i < lines.length; i++) {
			lines[i] = gaps[i].toString();
		}

		return lines;
	}

	/**
	 * Formats table of duplicate TSN values
	 * 
	 * @return multi-line table of duplicates
	 */
	@Field(offset = 24 * BYTE, length = 0, display = "Duplicate TSN", format = "%s[]")
	public String[] printDuplicateTSNs() {
		long[] dups = duplicates();
		String[] lines = new String[dups.length];

		for (int i = 0; i < lines.length; i++) {
			lines[i] = Long.toString(dups[i]);
		}

		return lines;
	}

	/**
	 * Gets an array of GapBlocks from the header
	 * 
	 * @return array of blocks
	 */
	public GapBlock[] gaps() {
		return gaps(new GapBlock[gapBlockCount()]);
	}

	/**
	 * Gets an array of GapBlocks from the header. Writes data in place. If the
	 * array already contains previously allocated GapBlock objects, they are
	 * peered against actual memory and reused. Otherwise new elements are
	 * allocated and stored in the array.
	 * 
	 * @param gaps
	 *            destination array where to write the blocks
	 * @return gaps array
	 */
	public GapBlock[] gaps(GapBlock[] gaps) {
		int count = gapBlockCount();

		for (int i = 0; i < count && i < gaps.length; i++) {
			if (gaps[i] == null) {
				gaps[i] = new GapBlock(this, 16 + (i * 4));
			} else {
				gaps[i].peer(this, 16 + (i * 4), 4);
			}
		}

		return gaps;
	}

	/**
	 * Gets an array of duplicate TSN values from the header
	 * 
	 * @return array of duplicates
	 */
	public long[] duplicates() {
		return duplicates(new long[duplicateTSNCount()]);
	}

	/**
	 * Gets an array of duplicates TSN values from the header
	 * 
	 * @param dups
	 *            destination array where to store duplicate values
	 * @return
	 */
	public long[] duplicates(long[] dups) {
		int count = duplicateTSNCount();
		int offset = 16 + (gapBlockCount() * 4);

		for (int i = 0; i < count && i < dups.length; i++) {
			dups[i] = super.getUInt(offset + (i * 4));
		}

		return dups;
	}

	public static class GapBlock extends JBuffer {

		public GapBlock(JBuffer buffer, int offset) {
			super(Type.POINTER);

			this.peer(buffer, offset, 4);
			this.order(ByteOrder.BIG_ENDIAN);
		}

		public int start() {
			return super.getUShort(0);
		}

		public int end() {
			return super.getUShort(2);
		}

		public String toString() {
			return String.format("[%d - %d]", start(), end());
		}
	}

}
