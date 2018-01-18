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

import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * Abort Association (ABORT) (6)
 * <p>
 * The ABORT chunk is sent to the peer of an association to close the
 * association. The ABORT chunk may contain Cause Parameters to inform the
 * receiver about the reason of the abort. DATA chunks MUST NOT be bundled with
 * ABORT. Control chunks (except for INIT, INIT ACK, and SHUTDOWN COMPLETE) MAY
 * be bundled with an ABORT, but they MUST be placed before the ABORT in the
 * SCTP packet or they will be ignored by the receiver.
 * </p>
 * <p>
 * If an endpoint receives an ABORT with a format error or no TCB is found, it
 * MUST silently discard it. Moreover, under any circumstances, an endpoint that
 * receives an ABORT MUST NOT respond to that ABORT by sending an ABORT of its
 * own.
 * </p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 6    |Reserved     |T|           Length              |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        \                                                               \
 *        /                   zero or more Error Causes                   /
 *        \                                                               \
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Abort Association", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-abort")
public class SctpAbort extends SctpChunk {
	
	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_ABORT_ID;


	private static final int SCTP_ABORT_T_FLAG = 0x01;

	/**
	 * Description of the current state of the T bit in flags
	 * 
	 * @return description string of the state of the T bit
	 */
	@Dynamic(field = "flags_T", value = Field.Property.DESCRIPTION)
	public String flags_TDescription() {
		return flags_T() == 1
				? "Sender filled Verification Tag"
				: "Verfication Tag is Reflected";
	}

	/**
	 * T bit: 1 bit
	 * <p>
	 * The T bit is set to 0 if the sender filled in the Verification Tag
	 * expected by the peer. If the Verification Tag is reflected, the T bit
	 * MUST be set to 1. Reflecting means that the sent Verification Tag is the
	 * same as the received one.
	 * </p>
	 * 
	 * @return returns value of T bit in flags
	 */
	@Field(offset = 0, length = 1, display = " T: Verification Tag")
	public int flags_T() {
		return flags() & SCTP_ABORT_T_FLAG;
	}

}
