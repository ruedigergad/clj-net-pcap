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

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.protocol.JProtocol;

/**
 * Baseclass for all Real-Time-Control-Protocol (RTCP) packet-types.
 * 
 * <pre>
 * SR: Sender report, for transmission and reception statistics from
 * participants that are active senders
 * 
 * RR: Receiver report, for reception statistics from participants that are not
 * active senders and in combination with SR for active senders reporting on
 * more than 31 sources
 * 
 * SDES: Source description items, including CNAME
 * 
 * BYE: Indicates end of participation
 * 
 * APP: Application-specific functions
 * </pre>
 * <p>
 * Each RTCP packet begins with a fixed part similar to that of RTP data
 * packets, followed by structured elements that MAY be of variable length
 * according to the packet type but MUST end on a 32-bit boundary. The alignment
 * requirement and a length field in the fixed part of each packet are included
 * to make RTCP packets "stackable". Multiple RTCP packets can be concatenated
 * without any intervening separators to form a compound RTCP packet that is
 * sent in a single packet of the lower layer protocol, for example UDP. There
 * is no explicit count of individual RTCP packets in the compound packet since
 * the lower layer protocols are expected to provide an overall length to
 * determine the end of the compound packet.
 * </p>
 * <p>
 * Each individual RTCP packet in the compound packet may be processed
 * independently with no requirements upon the order or combination of packets.
 * However, in order to perform the functions of the protocol, the following
 * constraints are imposed:
 * </p>
 * <p>
 * o Reception statistics (in SR or RR) should be sent as often as bandwidth
 * constraints will allow to maximize the resolution of the statistics,
 * therefore each periodically transmitted compound RTCP packet MUST include a
 * report packet.
 * </p>
 * <p>
 * o New receivers need to receive the CNAME for a source as soon as possible to
 * identify the source and to begin associating media for purposes such as
 * lip-sync, so each compound RTCP packet MUST also include the SDES CNAME
 * except when the compound RTCP packet is split for partial encryption as
 * described in Section 9.1.
 * </p>
 * <p>
 * o The number of packet types that may appear first in the compound packet
 * needs to be limited to increase the number of constant bits in the first word
 * and the probability of successfully validating RTCP packets against
 * misaddressed RTP data packets or other unrelated packets.
 * </p>
 * 
 * <pre>
 *    Thus, all RTCP packets MUST be sent in a compound packet of at least
 *    two individual packets, with the following format:
 * 
 *    Encryption prefix:  If and only if the compound packet is to be
 *       encrypted according to the method in Section 9.1, it MUST be
 *       prefixed by a random 32-bit quantity redrawn for every compound
 *       packet transmitted.  If padding is required for the encryption, it
 *       MUST be added to the last packet of the compound packet.
 * 
 *    SR or RR:  The first RTCP packet in the compound packet MUST
 *       always be a report packet to facilitate header validation as
 *       described in Appendix A.2.  This is true even if no data has been
 *       sent or received, in which case an empty RR MUST be sent, and even
 *       if the only other RTCP packet in the compound packet is a BYE.
 * 
 *    Additional RRs:  If the number of sources for which reception
 *       statistics are being reported exceeds 31, the number that will fit
 *       into one SR or RR packet, then additional RR packets SHOULD follow
 *       the initial report packet.
 * 
 *    SDES:  An SDES packet containing a CNAME item MUST be included
 *       in each compound RTCP packet, except as noted in Section 9.1.
 *       Other source description items MAY optionally be included if
 *       required by a particular application, subject to bandwidth
 *       constraints (see Section 6.3.9).
 * 
 *    BYE or APP:  Other RTCP packet types, including those yet to be
 *       defined, MAY follow in any order, except that BYE SHOULD be the
 *       last packet sent with a given SSRC/CSRC.  Packet types MAY appear
 *       more than once.
 * </pre>
 * 
 * 
 * </p>
 * <p>
 * The RTCP header (1st section) has the following format:
 * 
 * <pre>
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|    RC   |     Type      |             length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         SSRC of sender   (optional)           |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * </pre>
 * 
 * Note: SSRC is defined in RtcpSSCR header definition class
 * </p>
 * 
 * @author Sly Technologies, Inc.
 * @see RFC3550
 * @since 1.4
 */
public abstract class Rtcp extends JHeader {

	/**
	 * A combined bitmask that can be used to test for presence of any of the
	 * Rtcp based headers within a packet using
	 * <code>JPacket.hasAnyHeader</code> and <code>JPacket.hasAllHeaders</code>.
	 * 
	 * @see JPacket#hasAllHeaders(long)
	 * @see JPacket#hasAnyHeader(long)
	 */
	public final static long RTCP_HEADERS_BITMASK = JProtocol
			.createMaskFromIds(RtcpSenderReport.ID, RtcpReceiverReport.ID,
					RtcpSDES.ID, RtcpApp.ID, RtcpBye.ID);

	/**
	 * Table of supported Rtcp packet-types
	 * 
	 * @author Sly Technologies Inc.
	 */
	public enum PacketType {

		/** SR: Sender Report RTCP Packet */
		SENDER_REPORT(200, "SR"),

		/** RR: Receiver Report RTCP Packet */
		RECEIVER_REPORT(201, "RR"),

		/** SDES: Source Description RTCP Packet */
		SOURCE_DESCRIPTION(202, "SDES"),

		/** BYE: Goodbye RTCP Packet */
		BYE(203, "BYE"),

		/** APP: Application-Defined RTCP Packet */
		APPLICATION_DEFINED(204, "APP"),

		;
		private final int type;
		private final String abr;

		private PacketType(int type, String abr) {
			this.type = type;
			this.abr = abr;
		}

		/**
		 * Converts integer type to a constant
		 * 
		 * @param type
		 *            integer Rtcp packet-type code
		 * @return constant or null if not matched
		 */
		public static PacketType valueOf(int type) {
			for (PacketType pt : values()) {
				if (pt.type == type) {
					return pt;
				}
			}

			return null;
		}

		/**
		 * Gets a Abbreviated name for this packet-type
		 * 
		 * @return a short abbreviation
		 */
		public String getAbbreviation() {
			return this.abr;
		}

		/**
		 * Gets the integer packet-type Rtcp value for this packet-type
		 * 
		 * @return integer Rtcp type
		 */
		public int getPacketType() {
			return this.type;
		}
	}

	/**
	 * Protocol description.
	 */
	public final static String DESCRIPTION = "RTP Control Information";

	/**
	 * Protocol specification source
	 */
	public final static String RFC = "RFC3550";

	/**
	 * version (V): 2 bits
	 * <p>
	 * This field identifies the version of RTP. The version defined by this
	 * specification is two (2). (The value 1 is used by the first draft version
	 * of RTP and the value 0 is used by the protocol initially implemented in
	 * the "vat" audio tool.)
	 * </p>
	 * 
	 * @return version number of rtcp header
	 */
	@Field(offset = 0, length = 2, description = "RFC3550")
	public int version() {
		return (super.getByte(0) & 0xC0) >> 6;
	}

	/**
	 * padding (P): 1 bit
	 * <p>
	 * If the padding bit is set, this individual RTCP packet contains some
	 * additional padding octets at the end which are not part of the control
	 * information but are included in the length field. The last octet of the
	 * padding is a count of how many padding octets should be ignored,
	 * including itself (it will be a multiple of four). Padding may be needed
	 * by some encryption algorithms with fixed block sizes. In a compound RTCP
	 * packet, padding is only required on one individual packet because the
	 * compound packet is encrypted as a whole for the method in Section 9.1.
	 * Thus, padding MUST only be added to the last individual packet, and if
	 * padding is added to that packet, the padding bit MUST be set only on that
	 * packet. This convention aids the header validity checks described in
	 * Appendix A.2 and allows detection of packets from some early
	 * implementations that incorrectly set the padding bit on the first
	 * individual packet and add padding to the last individual packet.
	 * </p>
	 * 
	 * @return 1 indicates padding present, otherwise 0
	 */
	@Field(offset = 2, length = 1, display = "padding")
	public int isPadded() {
		return (super.getByte(0) & 0x20) >> 5;
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String typeDescription() {
		return PacketType.valueOf(type()).toString().replaceAll("_", " ");
	}

	/**
	 * packet type (PT): 8 bits
	 * <p>
	 * Contains the constant 200 to identify this as an RTCP SR packet.
	 * </p>
	 * 
	 * @return
	 */
	@Field(offset = 1 * BYTE, length = 1 * BYTE, display = "packet type")
	public int type() {
		return super.getUByte(1);
	}

	/**
	 * Description and detailed calculation for the length field
	 * 
	 * @return string with length calculated and described
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String lengthDescription() {
		return String.format("(%d +1) * 4 = %d bytes", length(),
				(length() + 1) << 2);
	}

	/**
	 * length: 16 bits
	 * <p>
	 * The length of this RTCP packet in 32-bit words minus one, including the
	 * header and any padding. (The offset of one makes zero a valid length and
	 * avoids a possible infinite loop in scanning a compound RTCP packet, while
	 * counting 32-bit words avoids a validity check for a multiple of 4.)
	 * </p>
	 * 
	 * @return number of 4-byte (32-bit) words that make up this packet
	 *         including the header -1
	 */
	@Field(offset = 2 * BYTE, length = 2 * BYTE, display = "packet length")
	public int length() {
		return super.getUShort(2);
	}

}
