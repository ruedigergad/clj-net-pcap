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
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.annotate.Field;

/**
 * Baseclass for all Real-Time-Control-Protocol (RTCP) packet-types that utilize
 * SSRC/CSRC field in the RTCP header.
 * 
 * <pre>
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|    RC   |     Type      |             length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         SSRC of sender                        |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * </pre>
 * 
 * @author Sly Technologies, Inc.
 * @see RFC3550
 * @since 1.4
 */
public abstract class RtcpSSRC extends Rtcp {

	/**
	 * SSRC: 32 bits
	 * <p>
	 * The synchronization source identifier for the originator of this SR
	 * packet.
	 * </p>
	 * 
	 * @return SSRC identifier
	 */
	@Field(offset = 4 * BYTE, length = 4 * BYTE, display = "ssrc/csrc", format = "%x")
	public long ssrc() {
		return super.getUInt(4);
	}
}
