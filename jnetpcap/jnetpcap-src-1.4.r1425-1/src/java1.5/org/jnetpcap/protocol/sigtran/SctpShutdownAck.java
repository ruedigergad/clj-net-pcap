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

import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * Shutdown Acknowledgement (SHUTDOWN ACK) (8)
 * <p>
 * This chunk MUST be used to acknowledge the receipt of the SHUTDOWN chunk at
 * the completion of the shutdown process; see RFC 4960 Section 9.2 for details.
 * </p>
 * <p>
 * The SHUTDOWN ACK chunk has no parameters.
 * </p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 8    |Chunk  Flags   |      Length = 4               |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Shutdown Acknowledgement", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-shut-ack")
public class SctpShutdownAck extends SctpChunk {

	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_SHUTDOWN_ACK_ID;

}
