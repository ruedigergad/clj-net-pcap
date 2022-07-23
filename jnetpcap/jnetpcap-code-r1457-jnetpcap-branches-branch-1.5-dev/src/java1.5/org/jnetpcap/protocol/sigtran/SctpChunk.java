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

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.HeaderLength;

/**
 * <pre>
 *    The figure below illustrates the field format for the chunks to be
 *    transmitted in the SCTP packet.  Each chunk is formatted with a Chunk
 *    Type field, a chunk-specific Flag field, a Chunk Length field, and a
 *    Value field.
 * 
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        \                                                               \
 *        /                          Chunk Value                          /
 *        \                                                               \
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
public abstract class SctpChunk extends JHeader {

	/**
	 * Payload Data
	 */
	public final static int DATA = 0;

	/**
	 * Initiation
	 */
	public final static int INIT = 1;

	/**
	 * Initiation Acknowledgement
	 */
	public final static int INIT_ACK = 2;

	/**
	 * Selective Acknowledgement
	 */
	public final static int SACK = 3;

	/**
	 * Heartbeat Request
	 */
	public final static int HEARTBEAT = 4;

	/**
	 * Heartbeat Acknowledgement
	 */
	public final static int HEARTBEAT_ACK = 5;

	/**
	 * Abort
	 */
	public final static int ABORT = 6;

	/**
	 * Shutdown
	 */
	public final static int SHUTDOWN = 7;

	/**
	 * Shutdown Acknowledgement
	 */
	public final static int SHUTDOWN_ACK = 8;

	/**
	 * Operation Error
	 */
	public final static int ERROR = 9;

	/**
	 * State Cookie
	 */
	public final static int COOKIE_ECHO = 10;

	/**
	 * Cookie Acknowledgement
	 */
	public final static int COOKIE_ACK = 11;

	/**
	 * Explicit Congestion Notification Echo
	 */
	public final static int ECNE = 12;

	/**
	 * Congestion Window Reduced
	 */
	public final static int CWR = 13;

	/**
	 * Shutdown Complete
	 */
	public final static int SHUTDOWN_COMPLETE = 14;

	public enum SctpChunkType {

		/**
		 * Payload Data
		 */
		DATA,

		/**
		 * Initiation
		 */
		INIT,

		/**
		 * Initiation Acknowledgement
		 */
		INIT_ACK,

		/**
		 * Selective Acknowledgement
		 */
		SACK,

		/**
		 * Heartbeat Request
		 */
		HEARTBEAT,

		/**
		 * Heartbeat Acknowledgement
		 */
		HEARTBEAT_ACK,

		/**
		 * Abort
		 */
		ABORT,

		/**
		 * Shutdown
		 */
		SHUTDOWN,

		/**
		 * Shutdown Acknowledgement
		 */
		SHUTDOWN_ACK,

		/**
		 * Operation Error
		 */
		ERROR,

		/**
		 * State Cookie
		 */
		COOKIE_ECHO,

		/**
		 * Cookie Acknowledgement
		 */
		COOKIE_ACK,

		/**
		 * Explicit Congestion Notification Echo
		 */
		ECNE,

		/**
		 * Congestion Window Reduced
		 */
		CWR,

		/**
		 * Shutdown Complete
		 */
		SHUTDOWN_COMPLETE;

		/**
		 * Converts integer protocol to a name
		 * 
		 * @param type
		 *            protocol to convert
		 * @return name as a string
		 */
		public static String valueOf(int type) {
			if (type < values().length) {
				return values()[type].toString();
			} else {
				return "Unassigned";
			}
		}

	}

	/**
	 * Mask for high-order 2 bits of the chunk type which specifies the action
	 * to be taken when unknown chunk type is encountered:
	 * <ul>
	 * <li>00 - Stop processing this SCTP packet and discard it, do not process
	 * any further chunks within it.
	 * <li>01 - Stop processing this SCTP packet and discard it, do not process
	 * any further chunks within it, and report the unrecognized chunk in an
	 * 'Unrecognized Chunk Type'.
	 * <li>10 - Skip this chunk and continue processing.
	 * <li>11 - Skip this chunk and continue processing, but report in an ERROR
	 * chunk using the 'Unrecognized Chunk Type' cause of error.
	 * 
	 * </ul>
	 */
	public final static int CHUNK_ACTION_MASK = 0xC0;

	/**
	 * (00) Stop processing this SCTP packet and discard it, do not process any
	 * further chunks within it. High order 2-bits of the type field.
	 */
	public final static int CHUNK_ACTION_STOP = 0x00;

	/**
	 * (01) Stop processing this SCTP packet and discard it, do not process any
	 * further chunks within it, and report the unrecognized chunk in an
	 * 'Unrecognized Chunk Type'. High order 2-bits of the type field.
	 */
	public final static int CHUNK_ACTION_STOP_AND_REPORT = 0x40;

	/**
	 * (10) Skip this chunk and continue processing. High order 2-bits of the
	 * type field. High order 2-bits of the type field.
	 */
	public final static int CHUNK_ACTION_SKIP = 0x80;

	/**
	 * (11) Skip this chunk and continue processing, but report in an ERROR
	 * chunk using the 'Unrecognized Chunk Type' cause of error. High order
	 * 2-bits of the type field.
	 */
	public final static int CHUNK_ACTION_ERROR = 0xC0;

	@HeaderLength
	public static int getHeaderLength(JBuffer buffer, int offset) {
		int len = buffer.getUShort(offset + 2);
		return len + (4 - len % 4) & 3;
	}

	/**
	 * The usage of these bits depends on the Chunk type as given by the Chunk
	 * Type field. Unless otherwise specified, they are set to 0 on transmit and
	 * are ignored on receipt.
	 * 
	 * @return value of the flags field
	 */
	@Field(offset = 1 * BYTE, length = 1 * BYTE, format = "%X")
	public int flags() {
		return super.getUByte(1);
	}

	@Field(parent = "flags", display = "CA: if chunk not recognized", offset = 6, length = 2)
	public int flags_Action() {
		return (flags() & CHUNK_ACTION_MASK) >> 6;
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String flags_ActionDescription() {
		switch (flags_Action()) {
			case 0 :
				return "stop and discard";
			case 1 :
				return "stop, discard and report";
			case 2 :
				return "skip and continue";
			case 3 :
				return "skip, continue and report";
		}
		return "unknown option";
	}

	/**
	 * The usage of these bits depends on the Chunk type as given by the Chunk
	 * Type field. Unless otherwise specified, they are set to 0 on transmit and
	 * are ignored on receipt.
	 * 
	 * @param value
	 *            new flags
	 */
	public void flags(int value) {
		super.setUByte(1, value);
	}

	/**
	 * This value represents the size of the chunk in bytes, including the Chunk
	 * Type, Chunk Flags, Chunk Length, and Chunk Value fields. Therefore, if
	 * the Chunk Value field is zero-length, the Length field will be set to 4.
	 * The Chunk Length field does not count any chunk padding.
	 * <p>
	 * Chunks (including Type, Length, and Value fields) are padded out by the
	 * sender with all zero bytes to be a multiple of 4 bytes long. This padding
	 * MUST NOT be more than 3 bytes in total. The Chunk Length value does not
	 * include terminating padding of the chunk. However, it does include
	 * padding of any variable-length parameter except the last parameter in the
	 * chunk. The receiver MUST ignore the padding.
	 * </p>
	 * Note: A robust implementation should accept the chunk whether or not the
	 * final padding has been included in the Chunk Length.
	 * <p>
	 * 
	 * @return length of the chunk, including the chunk header, in octets, but
	 *         excluding 4-byte padding which is implicit
	 */
	@Field(offset = 2 * BYTE, length = 2 * BYTE, format = "%d", units = "bytes")
	public int length() {
		return super.getUShort(2);
	}

	/**
	 * Sets the field whose value represents the size of the chunk in bytes,
	 * including the Chunk Type, Chunk Flags, Chunk Length, and Chunk Value
	 * fields. Therefore, if the Chunk Value field is zero-length, the Length
	 * field will be set to 4. The Chunk Length field does not count any chunk
	 * padding.
	 * <p>
	 * Chunks (including Type, Length, and Value fields) are padded out by the
	 * sender with all zero bytes to be a multiple of 4 bytes long. This padding
	 * MUST NOT be more than 3 bytes in total. The Chunk Length value does not
	 * include terminating padding of the chunk. However, it does include
	 * padding of any variable-length parameter except the last parameter in the
	 * chunk. The receiver MUST ignore the padding.
	 * </p>
	 * Note: A robust implementation should accept the chunk whether or not the
	 * final padding has been included in the Chunk Length.
	 * <p>
	 * 
	 * @param value
	 *            length of the chunk, including the chunk header, in octets,
	 *            but excluding 4-byte padding which is implicit
	 */
	public void length(int value) {
		super.setUShort(2, value);
	}

	/**
	 * This field identifies the type of information contained in the Chunk
	 * Value field. It takes a value from 0 to 254. The value of 255 is reserved
	 * for future use as an extension field.
	 * <p>
	 * The values of Chunk Types are defined as follows:
	 * <ol start=0>
	 * <li>Payload Data (DATA)
	 * <li>Initiation (INIT)
	 * <li>Initiation Acknowledgement (INIT ACK)
	 * <li>Selective Acknowledgement (SACK)
	 * <li>Heartbeat Request (HEARTBEAT)
	 * <li>Heartbeat Acknowledgement (HEARTBEAT ACK)
	 * <li>Abort (ABORT)
	 * <li>Shutdown (SHUTDOWN)
	 * <li>Shutdown Acknowledgement (SHUTDOWN ACK)
	 * <li>Operation Error (ERROR)
	 * <li>State Cookie (COOKIE ECHO)
	 * <li>Cookie Acknowledgement (COOKIE ACK)
	 * <li>Reserved for Explicit Congestion Notification Echo (ECNE)
	 * <li>Reserved for Congestion Window Reduced (CWR)
	 * <li>Shutdown Complete (SHUTDOWN COMPLETE)
	 * </ol>
	 * </p>
	 * 
	 * @return chunk type
	 * @see RFC4960
	 */
	@Field(offset = 0 * BYTE, length = 1 * BYTE, format = "%d")
	public int type() {
		return super.getUByte(0);
	}

	/**
	 * Description of the type value
	 * 
	 * @return description
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String typeDescription() {
		return SctpChunkType.valueOf(type()).toString();
	}
	/**
	 * Sets the value within the chunk header of SCTP packet. This field
	 * identifies the type of information contained in the Chunk Value field. It
	 * takes a value from 0 to 254. The value of 255 is reserved for future use
	 * as an extension field.
	 * <p>
	 * The values of Chunk Types are defined as follows:
	 * <ol start=0>
	 * <li>Payload Data (DATA)
	 * <li>Initiation (INIT)
	 * <li>Initiation Acknowledgement (INIT ACK)
	 * <li>Selective Acknowledgement (SACK)
	 * <li>Heartbeat Request (HEARTBEAT)
	 * <li>Heartbeat Acknowledgement (HEARTBEAT ACK)
	 * <li>Abort (ABORT)
	 * <li>Shutdown (SHUTDOWN)
	 * <li>Shutdown Acknowledgement (SHUTDOWN ACK)
	 * <li>Operation Error (ERROR)
	 * <li>State Cookie (COOKIE ECHO)
	 * <li>Cookie Acknowledgement (COOKIE ACK)
	 * <li>Reserved for Explicit Congestion Notification Echo (ECNE)
	 * <li>Reserved for Congestion Window Reduced (CWR)
	 * <li>Shutdown Complete (SHUTDOWN COMPLETE)
	 * </ol>
	 * </p>
	 * 
	 * @param value
	 *            chunk type
	 * 
	 * @see RFC4960
	 */
	public void type(int value) {
		super.setUByte(0, value);
	}
}
