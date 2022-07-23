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
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.format.FormatUtils;

/**
 * Initiation SCTP Chunk(INIT) (1) & Initiation ACK SCTP Chunk (INIT_ACK) (2)
 * base class.
 * <p>
 * This chunk is used to initiate an SCTP association between two endpoints. The
 * format of the INIT chunk is shown below:
 * </p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 1    |  Chunk Flags  |      Chunk Length             |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                         Initiate Tag                          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |           Advertised Receiver Window Credit (a_rwnd)          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |  Number of Outbound Streams   |  Number of Inbound Streams    |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                          Initial TSN                          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        \                                                               \
 *        /              Optional/Variable-Length Parameters              /
 *        \                                                               \
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * The INIT chunk contains the following parameters. Unless otherwise noted,
 * each parameter MUST only be included once in the INIT chunk.
 * 
 * <pre>
 *             Fixed Parameters                     Status
 *             ----------------------------------------------
 *             Initiate Tag                        Mandatory
 *             Advertised Receiver Window Credit   Mandatory
 *             Number of Outbound Streams          Mandatory
 *             Number of Inbound Streams           Mandatory
 *             Initial TSN                         Mandatory
 * 
 *           Variable Parameters                  Status     Type Value
 *           -------------------------------------------------------------
 *           IPv4 Address (Note 1)               Optional    5 IPv6 Address
 *           (Note 1)               Optional    6 Cookie Preservative
 *           Optional    9 Reserved for ECN Capable (Note 2)   Optional
 *           32768 (0x8000) Host Name Address (Note 3)          Optional
 *           11 Supported Address Types (Note 4)    Optional    12
 * </pre>
 * <p>
 * Note 1: The INIT chunks can contain multiple addresses that can be IPv4
 * and/or IPv6 in any combination.
 * </p>
 * <p>
 * Note 2: The ECN Capable field is reserved for future use of Explicit
 * Congestion Notification.
 * </p>
 * <p>
 * Note 3: An INIT chunk MUST NOT contain more than one Host Name Address
 * parameter. Moreover, the sender of the INIT MUST NOT combine any other
 * address types with the Host Name Address in the INIT. The receiver of INIT
 * MUST ignore any other address types if the Host Name Address parameter is
 * present in the received INIT chunk.
 * </p>
 * <p>
 * Note 4: This parameter, when present, specifies all the address types the
 * sending endpoint can support. The absence of this parameter indicates that
 * the sending endpoint can support any address type.
 * 
 * IMPLEMENTATION NOTE: If an INIT chunk is received with known parameters that
 * are not optional parameters of the INIT chunk, then the receiver SHOULD
 * process the INIT chunk and send back an INIT ACK. The receiver of the INIT
 * chunk MAY bundle an ERROR chunk with the COOKIE ACK chunk later. However,
 * restrictive implementations MAY send back an ABORT chunk in response to the
 * INIT chunk.
 * 
 * The Chunk Flags field in INIT is reserved, and all bits in it should be set
 * to 0 by the sender and ignored by the receiver. The sequence of parameters
 * within an INIT can be processed in any order.
 * </p>
 * <h4>Initiate Tag: 32 bits (unsigned integer)</h4>
 * 
 * The receiver of the INIT (the responding end) records the value of the
 * Initiate Tag parameter. This value MUST be placed into the Verification Tag
 * field of every SCTP packet that the receiver of the INIT transmits within
 * this association. </p>
 * <p>
 * The Initiate Tag is allowed to have any value except 0. See RFC 4960 Section 5.3.1 for
 * more on the selection of the tag value.
 * </p>
 * <p>
 * If the value of the Initiate Tag in a received INIT chunk is found to be 0,
 * the receiver MUST treat it as an error and close the association by
 * transmitting an ABORT.
 * </p>
 * <h4>Advertised Receiver Window Credit (a_rwnd): 32 bits (unsigned integer)</h4>
 * 
 * This value represents the dedicated buffer space, in number of bytes, the
 * sender of the INIT has reserved in association with this window. During the
 * life of the association, this buffer space SHOULD NOT be lessened (i.e.,
 * dedicated buffers taken away from this association); however, an endpoint MAY
 * change the value of a_rwnd it sends in SACK chunks.
 * 
 * <h4>Number of Outbound Streams (OS): 16 bits (unsigned integer)</h4>
 * 
 * Defines the number of outbound streams the sender of this INIT chunk wishes
 * to create in this association. The value of 0 MUST NOT be used. </p>
 * <p>
 * Note: A receiver of an INIT with the OS value set to 0 SHOULD abort the
 * association.
 * </p>
 * <h4>Number of Inbound Streams (MIS): 16 bits (unsigned integer)</h4>
 * 
 * Defines the maximum number of streams the sender of this INIT chunk allows
 * the peer end to create in this association. The value 0 MUST NOT be used.
 * </p>
 * <p>
 * Note: There is no negotiation of the actual number of streams but instead the
 * two endpoints will use the min(requested, offered). See RFC 4960 Section 5.1.1 for
 * details.
 * </p>
 * <p>
 * Note: A receiver of an INIT with the MIS value of 0 SHOULD abort the
 * association.
 * </p>
 * <h4>Initial TSN (I-TSN): 32 bits (unsigned integer)</h4>
 * 
 * Defines the initial TSN that the sender will use. The valid range is from 0
 * to 4294967295. This field MAY be set to the value of the Initiate Tag field.
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
public abstract class SctpInitBaseclass extends SctpChunk {

	public static class AddressTypeTLV extends TLV {

		/**
		 * @param buffer
		 * @param offset
		 * @param length
		 */
		public AddressTypeTLV(JBuffer buffer, int offset, int length) {
			super(buffer, offset, length);
		}

		public int[] addressTypes() {
			return addressTypes(new int[count()]);
		}

		public int[] addressTypes(int[] types) {

			for (int i = 0; i < types.length; i++) {
				types[i] = super.getUShort(4 + (i * 2));
			}

			return types;
		}

		public int count() {
			int length = super.length();
			return (length - 4) / 2;
		}

		public String toString() {
			final String MSG = "Supported Address Types: ";
			final StringBuilder b = new StringBuilder(MSG);

			for (int i : addressTypes()) {
				if (b.length() != MSG.length()) {
					b.append(", ");
				}

				b.append(i);
			}

			return b.toString();
		}
	}
	public static class CookieTLV extends TLV {

		/**
		 * @param buffer
		 * @param offset
		 * @param length
		 */
		public CookieTLV(JBuffer buffer, int offset, int length) {
			super(buffer, offset, length);
		}

		public long lifeSpan() {
			return super.getUInt(4);
		}

		public void lifeSpan(long timeout) {
			super.setUInt(4, timeout);
		}

		public String toString() {
			return String.format("Cookie Life-Span: %d ms", lifeSpan());
		}
	}

	public static class HostnameTLV extends TLV {

		/**
		 * @param buffer
		 * @param offset
		 * @param length
		 */
		public HostnameTLV(JBuffer buffer, int offset, int length) {
			super(buffer, offset, length);
		}

		public String hostname() {
			return super.getUTF8String(4, length() - 4);
		}

		public String toString() {
			return String.format("hostname: %s", hostname());
		}
	}

	public static class Ip4TLV extends TLV {

		/**
		 * @param buffer
		 * @param offset
		 * @param length
		 */
		public Ip4TLV(JBuffer buffer, int offset, int length) {
			super(buffer, offset, length);
		}

		public byte[] address() {
			return address(new byte[4]);
		}

		public byte[] address(byte[] dst) {
			if (dst.length != 4) {
				throw new IllegalArgumentException(
						"need 4 byte array for Ip4 address");
			}
			super.getByteArray(4, dst);
			return dst;
		}

		public void setAddress(byte[] src) {
			if (src.length != 4) {
				throw new IllegalArgumentException(
						"need 4 byte array for Ip4 address");
			}

			super.setByteArray(4, src);
		}

		public String toString() {
			return String.format("Ip4 Address: %s", FormatUtils.ip(address()));
		}
	}

	public static class Ip6TLV extends TLV {

		/**
		 * @param buffer
		 * @param offset
		 * @param length
		 */
		public Ip6TLV(JBuffer buffer, int offset, int length) {
			super(buffer, offset, length);
		}

		public byte[] address() {
			return address(new byte[16]);
		}

		public byte[] address(byte[] dst) {
			if (dst.length != 16) {
				throw new IllegalArgumentException(
						"need 16 byte array for Ip6 address");
			}
			super.getByteArray(4, dst);
			return dst;
		}

		public void setAddress(byte[] src) {
			if (src.length != 16) {
				throw new IllegalArgumentException(
						"need 16 byte array for Ip6 address");
			}

			super.setByteArray(4, src);
		}

		public String toString() {
			return String.format("Ip4 Address: %s", FormatUtils.ip(address()));
		}
	}

	public static class StateCookieTLV extends TLV {

		/**
		 * @param buffer
		 * @param offset
		 * @param length
		 */
		public StateCookieTLV(JBuffer buffer, int offset, int length) {
			super(buffer, offset, length);
		}

		public byte[] cookie() {
			return cookie(new byte[cookieLength()]);
		}

		public byte[] cookie(byte[] cookie) {
			return super.getByteArray(4, cookie);
		}

		public int cookieLength() {
			return length() - 4;
		}

		public String toString() {
			byte[] line = cookie(new byte[16]);
			return String
					.format("Cookie: %s", FormatUtils.hexLineData(line, 0));
		}
	}

	/**
	 * Baseclass for Type-Length-Value parameters. The following parameters
	 * follow the Type-Length-Value format as defined in RFC 4960 Section 3.2.1. Any
	 * Type-Length-Value fields MUST come after the fixed-length fields defined
	 * in the previous section.
	 * 
	 * 
	 * @author Sly Technologies Inc.
	 */
	public static class TLV extends JBuffer {

		/**
		 * SCTP Init Constants for supported Type-Length-Value parameters.
		 * 
		 * @author Sly Technologies Inc.
		 * @see RFC4960
		 */
		public enum TLVTypes {
			/**
			 * IPv4 Address Parameter (5)
			 */
			IPV4,

			/**
			 * IPv6 Address Parameter (6)
			 */
			IPV6,

			/**
			 * Cookie Preservative (9)
			 */
			COOKIE_LIFESPAN,

			/**
			 * Host Name Address (11)
			 */
			HOSTNAME,

			/**
			 * Supported Address Types (12)
			 */
			ADDRESS_TYPES;

		}

		/**
		 * IPv4 Address Parameter (5)
		 */
		public final static int IPV4_TLV = 5;

		/**
		 * IPv6 Address Parameter (6)
		 */
		public final static int IPV6_TLV = 6;

		/**
		 * State Cookie (7)
		 */
		public final static int STATE_COOKIE_TLV = 7;

		/**
		 * Unrecognized Parameter (8)
		 */
		public final static int UNRECOGNIZED_PARAMETER_TLV = 8;

		/**
		 * Cookie Preservative (9)
		 */
		public final static int COOKIE_LIFESPAN_TLV = 9;

		/**
		 * Host Name Address (11)
		 */
		public final static int HOSTNAME_TLV = 11;

		/**
		 * Supported Address Types (12)
		 */
		public final static int ADDRESS_TYPES_TLV = 12;

		public final static int ECN_TLV = 0x8000;

		public final static int FORWARD_TSN_TLV = 0xC000;

		public final static int ADAPTATION_LAYER_TLV = 0xC006;

		public static TLV create(JBuffer buffer, int offset) {
			int type = buffer.getUShort(offset);
			int length = buffer.getUShort(offset + 2);

			switch (type) {
				case 5 : // Ip4
					return new Ip4TLV(buffer, offset, length);

				case 6 : // Ip6
					return new Ip6TLV(buffer, offset, length);

				case 7 : // State Cookie
					return new StateCookieTLV(buffer, offset, length);

				case 8 : // Unrecognized Parameters
					return new UnrecognizedParametersTLV(buffer, offset, length);

				case 9 : // Cookie Preservative
					return new CookieTLV(buffer, offset, length);

				case 11 : // Host Name Address (11)
					return new HostnameTLV(buffer, offset, length);

				case 12 : // Supported Address Types (12)
					return new AddressTypeTLV(buffer, offset, length);

				case ECN_TLV : // Supported Address Types (12)
					return new TLV("ECN", buffer, offset, length);

				case FORWARD_TSN_TLV : // Supported Address Types (12)
					return new TLV("Forward TSN Supported", buffer, offset,
							length);

				case ADAPTATION_LAYER_TLV : // Supported Address Types (12)
					long indication = buffer.getUInt(offset + 4);
					return new TLV(String.format(
							"Adaptation Layer Indication: 0x%08X", indication),
							buffer, offset, length);

				default :
					return new TLV(String.format(
							"Unrecognized type=%04X, length=%d", type, length),
							buffer, offset, length);
			}
		}

		private final String label;

		public TLV(JBuffer buffer, int offset, int length) {
			super(Type.POINTER);

			this.peer(buffer, offset, length);
			this.order(ByteOrder.BIG_ENDIAN);
			this.label = "";
		}

		public TLV(String label, JBuffer buffer, int offset, int length) {
			super(Type.POINTER);
			this.label = label;

			this.peer(buffer, offset, length);
			this.order(ByteOrder.BIG_ENDIAN);
		}

		public int length() {
			return super.getUShort(2);
		}

		public void length(int value) {
			super.setUShort(2, value);
		}

		public String toString() {
			return label;
		}

		public int type() {
			return super.getUShort(0);
		}

		public void type(int value) {
			super.setUShort(0, value);
		}

	}

	public static class UnrecognizedParametersTLV extends TLV {

		private final int length;

		/**
		 * @param buffer
		 * @param offset
		 * @param length
		 */
		public UnrecognizedParametersTLV(JBuffer buffer, int offset, int length) {
			super(buffer, offset, length);
			this.length = length;
		}

		public int count() {

			int count = 0;
			for (int offset = 4; offset < length;) {
				int urecognizedTlvLen = super.getUShort(offset + 2);

				offset += urecognizedTlvLen;
				count++;
			}

			return count;
		}

		public TLV[] parameters() {
			return parameters(new TLV[count()]);
		}

		public TLV[] parameters(TLV[] params) {

			int offset = 4;
			for (int i = 0; i < params.length; i++) {
				int type = super.getUShort(offset);
				int alen = super.getUShort(offset + 2); // Actual len
				int len = alen + ((4 - alen % 4) & 3); // Pad to 4 bytes
				params[i] = new TLV(String.format("#%d[type=%X, len=%d]", type,
						len), this, offset, alen);

				offset += len;
			}

			return params;
		}

		public String toString() {
			final String MSG = "Supported Address Types: ";
			final StringBuilder b = new StringBuilder(MSG);

			for (TLV i : parameters()) {
				if (b.length() != MSG.length()) {
					b.append(", ");
				}

				b.append(i);
			}

			return b.toString();
		}
	}

	static TLV[] readTLVS(JBuffer buffer, int length) {
		final List<TLV> list = new ArrayList<TLV>();

		for (int offset = 20; offset < length;) {
			TLV tlv = TLV.create(buffer, offset);

			list.add(tlv);

			int tlvLen = buffer.getUShort(offset + 2);
			tlvLen = tlvLen + ((4 - tlvLen % 4) & 3);

			offset += tlvLen;
		}

		return list.toArray(new TLV[list.size()]);
	}

	/**
	 * Number of Inbound Streams (MIS): 16 bits (unsigned integer)
	 * <p>
	 * Defines the maximum number of streams the sender of this INIT chunk
	 * allows the peer end to create in this association. The value 0 MUST NOT
	 * be used.
	 * </p>
	 * <p>
	 * Note: There is no negotiation of the actual number of streams but instead
	 * the two endpoints will use the min(requested, offered). See RFC 4960 Section 5.1.1
	 * for details.
	 * </p>
	 * <p>
	 * Note: A receiver of an INIT with the MIS value of 0 SHOULD abort the
	 * association.
	 * </p>
	 * 
	 * @param value
	 *            number of inbound streams
	 */
	public void istream(int value) {
		super.setUShort(14, value);
	}

	/**
	 * Number of Inbound Streams (MIS): 16 bits (unsigned integer)
	 * <p>
	 * Defines the maximum number of streams the sender of this INIT chunk
	 * allows the peer end to create in this association. The value 0 MUST NOT
	 * be used.
	 * </p>
	 * <p>
	 * Note: There is no negotiation of the actual number of streams but instead
	 * the two endpoints will use the min(requested, offered). See RFC 4960 Section 5.1.1
	 * for details.
	 * </p>
	 * <p>
	 * Note: A receiver of an INIT with the MIS value of 0 SHOULD abort the
	 * association.
	 * </p>
	 * 
	 * @return number of inbound streams
	 */
	@Field(offset = 14 * BYTE, length = 2 * BYTE, display = "Inbound Streams")
	public int istreams() {
		return super.getUShort(14);
	}

	/**
	 * Number of Outbound Streams (OS): 16 bits (unsigned integer)
	 * <p>
	 * Defines the number of outbound streams the sender of this INIT chunk
	 * wishes to create in this association. The value of 0 MUST NOT be used.
	 * </p>
	 * <p>
	 * Note: A receiver of an INIT with the OS value set to 0 SHOULD abort the
	 * association.
	 * </p>
	 * 
	 * @param value
	 *            number of outbound streams
	 */
	public void ostream(int value) {
		super.setUShort(12, value);
	}

	/**
	 * Number of Outbound Streams (OS): 16 bits (unsigned integer)
	 * <p>
	 * Defines the number of outbound streams the sender of this INIT chunk
	 * wishes to create in this association. The value of 0 MUST NOT be used.
	 * </p>
	 * <p>
	 * Note: A receiver of an INIT with the OS value set to 0 SHOULD abort the
	 * association.
	 * </p>
	 * 
	 * @return number of outbound streams
	 */
	@Field(offset = 12 * BYTE, length = 2 * BYTE, display = "Outbound Streams")
	public int ostreams() {
		return super.getUShort(12);
	}

	@Field(offset = 20 * BYTE, length = 0, display = "TLV Parameter", format = "%s[]")
	public String[] printTlvs() {
		final TLV[] tlvs = tlvs();
		final String[] labels = new String[tlvs.length];

		for (int i = 0; i < tlvs.length; i++) {
			labels[i] = tlvs[i].toString();
		}

		return labels;
	}

	/**
	 * Initiate Tag: 32 bits (unsigned integer)
	 * <p>
	 * The receiver of the INIT (the responding end) records the value of the
	 * Initiate Tag parameter. This value MUST be placed into the Verification
	 * Tag field of every SCTP packet that the receiver of the INIT transmits
	 * within this association.
	 * </p>
	 * <p>
	 * The Initiate Tag is allowed to have any value except 0. See RFC 4960 Section 5.3.1
	 * for more on the selection of the tag value.
	 * </p>
	 * <p>
	 * If the value of the Initiate Tag in a received INIT chunk is found to be
	 * 0, the receiver MUST treat it as an error and close the association by
	 * transmitting an ABORT.
	 * </p>
	 * 
	 * @return initiate tag (unsinged 32-bit)
	 */
	@Field(offset = 4 * BYTE, length = 4 * BYTE, display = "Initiate Tag")
	public long tag() {
		return super.getUInt(4);
	}

	/**
	 * Initiate Tag: 32 bits (unsigned integer)
	 * <p>
	 * The receiver of the INIT (the responding end) records the value of the
	 * Initiate Tag parameter. This value MUST be placed into the Verification
	 * Tag field of every SCTP packet that the receiver of the INIT transmits
	 * within this association.
	 * </p>
	 * <p>
	 * The Initiate Tag is allowed to have any value except 0. See RFC 4960 Section 5.3.1
	 * for more on the selection of the tag value.
	 * </p>
	 * <p>
	 * If the value of the Initiate Tag in a received INIT chunk is found to be
	 * 0, the receiver MUST treat it as an error and close the association by
	 * transmitting an ABORT.
	 * </p>
	 * 
	 * @param value
	 *            initiate tag (unsinged 32-bit)
	 */
	public void tag(long value) {
		super.setUInt(4, value);
	}

	/**
	 * Gets an array of Type-Length-Value parameters from the header
	 * 
	 * @return array of TLVs
	 */
	public TLV[] tlvs() {
		return readTLVS(this, length());
	}

	/**
	 * Initial TSN (I-TSN): 32 bits (unsigned integer)
	 * <p>
	 * Defines the initial TSN that the sender will use. The valid range is from
	 * 0 to 4294967295. This field MAY be set to the value of the Initiate Tag
	 * field.
	 * </p>
	 * 
	 * @return initial TSN value
	 */
	@Field(offset = 16 * BYTE, length = 4 * BYTE, display = "Initial TSN", format = "%lx")
	public long tsn() {
		return super.getUInt(16);
	}

	/**
	 * Initial TSN (I-TSN): 32 bits (unsigned integer)
	 * <p>
	 * Defines the initial TSN that the sender will use. The valid range is from
	 * 0 to 4294967295. This field MAY be set to the value of the Initiate Tag
	 * field.
	 * </p>
	 * 
	 * @param value
	 *            initial TSN value
	 */
	public void tsn(long value) {
		super.setUInt(16, value);
	}

	/**
	 * Advertised Receiver Window Credit (a_rwnd): 32 bits (unsigned integer)
	 * </p>
	 * <p>
	 * This value represents the dedicated buffer space, in number of bytes, the
	 * sender of the INIT has reserved in association with this window. During
	 * the life of the association, this buffer space SHOULD NOT be lessened
	 * (i.e., dedicated buffers taken away from this association); however, an
	 * endpoint MAY change the value of a_rwnd it sends in SACK chunks.
	 * </p>
	 * 
	 * @return window credit
	 */
	@Field(offset = 8 * BYTE, length = 4 * BYTE, display = "Advertised Receiver Window Credit")
	public long window() {
		return super.getUInt(8);
	}

	/**
	 * Advertised Receiver Window Credit (a_rwnd): 32 bits (unsigned integer)
	 * </p>
	 * <p>
	 * This value represents the dedicated buffer space, in number of bytes, the
	 * sender of the INIT has reserved in association with this window. During
	 * the life of the association, this buffer space SHOULD NOT be lessened
	 * (i.e., dedicated buffers taken away from this association); however, an
	 * endpoint MAY change the value of a_rwnd it sends in SACK chunks.
	 * </p>
	 * 
	 * @param value
	 *            window credit
	 */
	public void window(long value) {
		super.setUInt(8, value);
	}

}
