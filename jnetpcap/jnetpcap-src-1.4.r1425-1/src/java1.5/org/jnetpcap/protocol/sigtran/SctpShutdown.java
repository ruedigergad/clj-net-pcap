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
 * Shutdown Association (SHUTDOWN) (7)
 * <p>
 * An endpoint in an association MUST use this chunk to initiate a graceful
 * close of the association with its peer. This chunk has the following format.
 * </p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 7    | Chunk  Flags  |      Length = 8               |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                      Cumulative TSN Ack                       |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Shutdown Association", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-shut")
public class SctpShutdown extends SctpChunk {
	
	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_SHUTDOWN_ID;

	/**
	 * This parameter contains the TSN of the last chunk received in sequence
	 * before any gaps.
	 * 
	 * @return TSN number
	 */
	@Field(offset = 4 * BYTE, length = 4 * BYTE, display = "Cumulative TSN Ack", format = "%x")
	public long ack() {
		return super.getUInt(4);
	}

	/**
	 * This parameter contains the TSN of the last chunk received in sequence
	 * before any gaps.
	 * 
	 * @param value
	 *            TSN number
	 */
	public void ack(long value) {
		super.setUInt(4, value);
	}
}
