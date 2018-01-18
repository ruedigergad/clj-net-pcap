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
 * Operation Error (ERROR) (9)
 * <p>
 * An endpoint sends this chunk to its peer endpoint to notify it of certain
 * error conditions. It contains one or more error causes. An Operation Error is
 * not considered fatal in and of itself, but may be used with an ABORT chunk to
 * report a fatal condition. It has the following parameters:
 * </p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 9    | Chunk  Flags  |           Length              |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        \                                                               \
 *        /                    one or more Error Causes                   /
 *        \                                                               \
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Operation Error", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-error")
public class SctpError extends SctpChunk {

	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_ERROR_ID;

}
