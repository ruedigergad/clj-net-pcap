/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
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
package org.jnetpcap.protocol.network;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;

// TODO: Auto-generated Javadoc
/**
 * Address Resolution Protocol header. ARP is used to translate protocol
 * addresses to hardware interface addresses.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
public class Arp
    extends
    JHeader {

	/**
	 * Header length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		final int hlen = buffer.getUByte(offset + 4);
		final int plen = buffer.getUByte(offset + 5);

		return (hlen + plen) * 2 + 8;
	}

	/** The sha offset. */
	private int shaOffset;

	/** The spa offset. */
	private int spaOffset;

	/** The tha offset. */
	private int thaOffset;

	/** The tpa offset. */
	private int tpaOffset;

	/**
	 * Definitions for ARP supported hardware types.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum HardwareType {
		
		/** The RESERVE d1. */
		RESERVED1,
		
		/** The ETHERNET. */
		ETHERNET,
		
		/** The EXSPERIMENTA l_ ethernet. */
		EXSPERIMENTAL_ETHERNET,
		
		/** The AMATEU r_ radi o_ a x_25. */
		AMATEUR_RADIO_AX_25,
		
		/** The PROTEO n_ pr o_ ne t_ toke n_ ring. */
		PROTEON_PRO_NET_TOKEN_RING,
		
		/** The CHAOS. */
		CHAOS,
		
		/** The IEE e802. */
		IEEE802,
		
		/** The ARCNET. */
		ARCNET,
		
		/** The HYPERCHANNEL. */
		HYPERCHANNEL,
		
		/** The LANSTAR. */
		LANSTAR,
		
		/** The AUTONE t_ shor t_ address. */
		AUTONET_SHORT_ADDRESS,
		
		/** The LOCA l_ talk. */
		LOCAL_TALK,
		
		/** The LOCA l_ net. */
		LOCAL_NET,
		
		/** The ULTR a_ link. */
		ULTRA_LINK,
		
		/** The SMDS. */
		SMDS,
		
		/** The FRAM e_ relay. */
		FRAME_RELAY,
		
		/** The AT m1. */
		ATM1,
		
		/** The SERIA l_ line. */
		SERIAL_LINE,
		
		/** The AT m2. */
		ATM2,
		
		/** The MI l_ st d_188_220. */
		MIL_STD_188_220,
		
		/** The METRICOM. */
		METRICOM,
		
		/** The IEE e1395. */
		IEEE1395,
		
		/** The MAPOS. */
		MAPOS,
		
		/** The TWINAXIAL. */
		TWINAXIAL,
		
		/** The EU i64. */
		EUI64,
		
		/** The HIPARP. */
		HIPARP,
		
		/** The IS o7816_3. */
		ISO7816_3,
		
		/** The ARPSEC. */
		ARPSEC,
		
		/** The IPSE c_ tunnel. */
		IPSEC_TUNNEL,
		
		/** The INFINIBAND. */
		INFINIBAND,
		
		/** The CAI. */
		CAI,
		
		/** The WIEGAN d_ interface. */
		WIEGAND_INTERFACE,
		
		/** The PUR e_ id. */
		PURE_ID,
		
		/** The H w_ ex p1. */
		HW_EXP1, ;

		/**
		 * Convert a numerical protocol type number to constant.
		 * 
		 * @param value
		 *          value of the protocol type field
		 * @return corresponding constant or null if none matched
		 */
		public static HardwareType valueOf(int value) {
			return values()[value];
		}
	}

	/**
	 * Definitions for supported protocol types.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc@SuppressWarnings("unused") .
	 */
	public enum ProtocolType {
		
		/** The IP. */
		IP(0x800);

		/** The value. */
		@SuppressWarnings("unused")
		private final int value;

		/**
		 * Instantiates a new protocol type.
		 * 
		 * @param value
		 *          the value
		 */
		private ProtocolType(int value) {
			this.value = value;
		}

		/**
		 * Convert a numerical protocol type number to constant.
		 * 
		 * @param value
		 *          value of the protocol type field
		 * @return corresponding constant or null if none matched
		 */
		public static ProtocolType valueOf(int value) {
			if (value == 0x800) {
				return IP;
			}

			return null;
		}
	}

	/**
	 * Definitions for all the possible ARP operations as specified by the
	 * operation field.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum OpCode {
		
		/** The RESERVE d1. */
		RESERVED1,
		
		/** The REQUEST. */
		REQUEST,
		
		/** The REPLY. */
		REPLY,
		
		/** The REQUES t_ reverse. */
		REQUEST_REVERSE,
		
		/** The REPL y_ reverse. */
		REPLY_REVERSE,
		
		/** The DRAR p_ request. */
		DRARP_REQUEST,
		
		/** The DRAR p_ reply. */
		DRARP_REPLY,
		
		/** The DRAR p_ error. */
		DRARP_ERROR,
		
		/** The I n_ ar p_ request. */
		IN_ARP_REQUEST,
		
		/** The I n_ ar p_ reply. */
		IN_ARP_REPLY,
		
		/** The AR p_ nak. */
		ARP_NAK,
		
		/** The MAR s_ request. */
		MARS_REQUEST,
		
		/** The MAR s_ multi. */
		MARS_MULTI,
		
		/** The MAR s_ mserv. */
		MARS_MSERV,
		
		/** The MAR s_ join. */
		MARS_JOIN,
		
		/** The MAR s_ leave. */
		MARS_LEAVE,
		
		/** The MAR s_ nak. */
		MARS_NAK,
		
		/** The MAR s_ unserv. */
		MARS_UNSERV,
		
		/** The MAR s_ sjoin. */
		MARS_SJOIN,
		
		/** The MAR s_ sleave. */
		MARS_SLEAVE,
		
		/** The MAR s_ grou p_ lis t_ request. */
		MARS_GROUP_LIST_REQUEST,
		
		/** The MAR s_ grou p_ lis t_ replay. */
		MARS_GROUP_LIST_REPLAY,
		
		/** The MAR s_ redirec t_ map. */
		MARS_REDIRECT_MAP,
		
		/** The MAPO s_ unarp. */
		MAPOS_UNARP,
		
		/** The O p_ ex p1. */
		OP_EXP1,
		
		/** The O p_ ex p2. */
		OP_EXP2, ;

		/**
		 * Converts the operation field value to a constant.
		 * 
		 * @param value
		 *          operation field value
		 * @return constant or null
		 */
		public static OpCode valueOf(int value) {
			return values()[value];
		}
	}

	/**
	 * Hardware type description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String hardwareTypeDescription() {
		return hardwareTypeEnum().toString();
	}

	/**
	 * Hardware type.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, length = 16)
	public int hardwareType() {
		return super.getUShort(0);
	}

	/**
	 * Hardware type enum.
	 * 
	 * @return the hardware type
	 */
	public HardwareType hardwareTypeEnum() {
		return HardwareType.valueOf(hardwareType());
	}

	/**
	 * Protocol type.
	 * 
	 * @return the int
	 */
	@Field(offset = 2 * 8, format = "%x", length = 16)
	public int protocolType() {
		return super.getUShort(2);
	}

	/**
	 * Protocol type description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String protocolTypeDescription() {
		return protocolTypeEnum().toString();
	}

	/**
	 * Protocol type enum.
	 * 
	 * @return the protocol type
	 */
	public ProtocolType protocolTypeEnum() {
		return ProtocolType.valueOf(protocolType());
	}

	/**
	 * Hlen.
	 * 
	 * @return the int
	 */
	@Field(offset = 4 * 8, length = 8, units = "bytes", display = "hardware size")
	public int hlen() {
		return super.getUByte(4);
	}

	/**
	 * Plen.
	 * 
	 * @return the int
	 */
	@Field(offset = 5 * 8, length = 8, units = "bytes", display = "protocol size")
	public int plen() {
		return super.getUByte(5);
	}

	/**
	 * Operation description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String operationDescription() {
		return operationEnum().toString();
	}

	/**
	 * Operation.
	 * 
	 * @return the int
	 */
	@Field(offset = 6 * 8, length = 16, display = "op code")
	public int operation() {
		return super.getUShort(6);
	}

	/**
	 * Operation enum.
	 * 
	 * @return the op code
	 */
	public OpCode operationEnum() {
		return OpCode.valueOf(operation());
	}

	/**
	 * Sha.
	 * 
	 * @return the byte[]
	 */
	@Field(offset = 8 * 8, format = "#mac#", display = "sender MAC")
	public byte[] sha() {
		return super.getByteArray(this.shaOffset, hlen());
	}

	/**
	 * Sha length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int shaLength() {
		return hlen() * 8;
	}

	/**
	 * Spa.
	 * 
	 * @return the byte[]
	 */
	@Field(format = "#ip4#", display = "sender IP")
	public byte[] spa() {
		return super.getByteArray(this.spaOffset, plen());
	}

	/**
	 * Spa offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int spaOffset() {
		return this.spaOffset * 8;
	}

	/**
	 * Spa length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int spaLength() {
		return plen() * 8;
	}

	/**
	 * Tha.
	 * 
	 * @return the byte[]
	 */
	@Field(format = "#mac#", display = "target MAC")
	public byte[] tha() {
		return super.getByteArray(this.thaOffset, hlen());
	}

	/**
	 * Tha offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int thaOffset() {
		return this.thaOffset * 8;
	}

	/**
	 * Tha length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int thaLength() {
		return hlen() * 8;
	}

	/**
	 * Tpa.
	 * 
	 * @return the byte[]
	 */
	@Field(format = "#ip4#", display = "target IP")
	public byte[] tpa() {
		return super.getByteArray(this.tpaOffset, plen());
	}

	/**
	 * Tpa offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int tpaOffset() {
		return this.tpaOffset * 8;
	}

	/**
	 * Tpa length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int tpaLength() {
		return plen() * 8;
	}

	/**
	 * Decode header.
	 * 
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {

		/*
		 * Pre calculate offsets for variable length fields
		 */
		final int hlen = hlen();
		final int plen = plen();

		this.shaOffset = 8;
		this.spaOffset = shaOffset + hlen;

		this.thaOffset = spaOffset + plen;
		this.tpaOffset = thaOffset + hlen;
	}

}
