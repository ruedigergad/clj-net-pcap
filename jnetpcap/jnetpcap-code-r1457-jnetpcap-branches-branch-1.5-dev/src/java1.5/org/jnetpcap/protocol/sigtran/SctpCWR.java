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

import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * Congestion Window CWR (13)
 * <p>
 * [RFC3168] details a specific bit for a sender to send in the header of its
 * next outbound TCP segment to indicate to its peer that it has reduced its
 * congestion window. This is termed the CWR bit. For SCTP, the same indication
 * is made by including the CWR chunk. This chunk contains one data element,
 * i.e., the TSN number that was sent in the ECNE chunk. This element represents
 * the lowest TSN number in the datagram that was originally marked with the CE
 * bit.
 * </p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        | Chunk Type=13 | Flags=00000000|    Chunk Length = 8           |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                      Lowest TSN Number                        |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * Note: The CWR is considered a Control chunk.
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Congestion Window Request", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-CWR")
public class SctpCWR extends SctpChunk {
	
	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_CWR_ID;


	/**
	 * The lowest TSN associated with the IP datagram marked with the CE bit
	 * 
	 * @return tsn number
	 */
	@Field(offset = 4 * BYTE, length = 4 * BYTE, display = "Lowest TSN Number", format = "%x")
	public long tsn() {
		return super.getUInt(4);
	}

	/**
	 * The lowest TSN associated with the IP datagram marked with the CE bit
	 * 
	 * @param value
	 *            tsn number
	 */
	public void tsn(long value) {
		super.setUInt(4, value);
	}

}
