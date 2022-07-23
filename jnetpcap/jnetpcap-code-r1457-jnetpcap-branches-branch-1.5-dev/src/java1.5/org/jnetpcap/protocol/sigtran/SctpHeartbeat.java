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
 * Heartbeat Request (HEARTBEAT) (4)
 * <p>
 * An endpoint should send this chunk to its peer endpoint to probe the
 * reachability of a particular destination transport address defined in the
 * present association.
 * </p>
 * <p>
 * The parameter field contains the Heartbeat Information, which is a
 * variable-length opaque data structure understood only by the sender.
 * </p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 4    | Chunk  Flags  |      Heartbeat Length         |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        \                                                               \
 *        /            Heartbeat Information TLV (Variable-Length)        /
 *        \                                                               \
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * <p>
 * Heartbeat Information: variable length
 * </p>
 * <p>
 * Defined as a variable-length parameter using the format described in RFC 4960 Section
 * 3.2.1, i.e.:
 * </p>
 * 
 * <pre>
 *          Variable Parameters                  Status     Type Value
 *          -------------------------------------------------------------
 *          Heartbeat Info                       Mandatory   1
 * 
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |    Heartbeat Info Type=1      |         HB Info Length        |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        /                  Sender-Specific Heartbeat Info               /
 *        \                                                               \
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * </pre>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Heartbeat Request", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-hbeat")
public class SctpHeartbeat extends SctpChunk {
	
	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_HEARTBEAT_ID;


	/**
	 * Hearbeat type (1 - mandatory).
	 * 
	 * @return the type, typically 0x0001
	 */
	@Field(offset = 4 * BYTE, length = 2 * BYTE, display = "Heartbeat Info Type")
	public int infoType() {
		return super.getUShort(4);
	}

	/**
	 * Sets the heartbeat type
	 * 
	 * @param value
	 *            heartbeat type
	 */
	public void infoType(int value) {
		super.setUShort(4, value);
	}

	/**
	 * Length of the TLV field, including the info data and TLV header
	 * 
	 * @return length of TLV field
	 */
	@Field(offset = 6 * BYTE, length = 2 * BYTE, display = "Heartbeat Info Length")
	public int infoLength() {
		return super.getUShort(6);
	}

	/**
	 * Sets the TLV length field
	 * 
	 * @param value
	 *            length field value
	 */
	public void infoLength(int value) {
		super.setUShort(6, value);
	}

	/**
	 * Heartbeat info data. This is application specific.
	 * 
	 * @return array containing the heartbeat data
	 */
	@Field(offset = 8 * BYTE, length = 0 * BYTE, display = "Heartbeat Info", format = "#hexdump#")
	public byte[] info() {
		return info(new byte[infoLength() - 4]);
	}

	/**
	 * Heartbeat info data. This is application specific. The heartbeat info is
	 * stored into "array".
	 * 
	 * @return array containing the heartbeat data
	 */
	public byte[] info(byte[] array) {
		int lenField = infoLength() - 4;
		int len = (array.length < lenField ? array.length : lenField);

		super.getByteArray(8, array, 0, len);

		return array;
	}

}
