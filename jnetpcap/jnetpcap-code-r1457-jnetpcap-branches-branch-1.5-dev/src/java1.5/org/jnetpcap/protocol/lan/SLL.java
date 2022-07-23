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
package org.jnetpcap.protocol.lan;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * For captures on Linux cooked sockets, we construct a fake header that
 * includes: a 2-byte "packet type" which is one of: LINUX_SLL_HOST packet was
 * sent to us LINUX_SLL_BROADCAST packet was broadcast LINUX_SLL_MULTICAST
 * packet was multicast LINUX_SLL_OTHERHOST packet was sent to somebody else
 * LINUX_SLL_OUTGOING packet was sent *by* us; a 2-byte Ethernet protocol field;
 * a 2-byte link-layer type; a 2-byte link-layer address length; an 8-byte
 * source link-layer address, whose actual length is specified by the previous
 * value. All fields except for the link-layer address are in network byte
 * order. DO NOT change the layout of this structure, or change any of the
 * LINUX_SLL_ values below. If you must change the link-layer header for a
 * "cooked" Linux capture, introduce a new DLT_ type (ask
 * "tcpdump-workers@lists.tcpdump.org" for one, so that you don't give it a
 * value that collides with a value already being used), and use the new header
 * in captures of that type, so that programs that can handle DLT_LINUX_SLL
 * captures will continue to handle them correctly without any change, and so
 * that capture files with different headers can be told apart and programs that
 * read them can dissect the packets in them.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * 
 * <pre>
 *  #define SLL_HDR_LEN	16		          // total header length
 *  #define SLL_ADDRLEN	8		            // length of address field
 * 
 *  struct sll_header {
 *    u_int16_t	sll_pkttype;	          // packet type
 *    u_int16_t	sll_hatype;	            // link-layer address type
 *    u_int16_t	sll_halen;	            // link-layer address length
 *    u_int8_t	sll_addr[SLL_ADDRLEN];	// link-layer address
 *    u_int16_t	sll_protocol;         	// protocol
 *  };
 * 
 * </pre>
 */
@Header(length = SLL.SLL_HDR_LEN, suite = ProtocolSuite.LAN, description = "Linux Cooked Capture")
public class SLL
    extends
    JHeader {

	/** The Constant SLL_HDR_LEN. */
	public final static int SLL_HDR_LEN = 16;

	/** The Constant LINUX_SLL_HOST. */
	public final static int LINUX_SLL_HOST = 0;

	/** The Constant LINUX_SLL_BROADCAST. */
	public final static int LINUX_SLL_BROADCAST = 1;

	/** The Constant LINUX_SLL_MULTICAST. */
	public final static int LINUX_SLL_MULTICAST = 2;

	/** The Constant LINUX_SLL_OTHERHOST. */
	public final static int LINUX_SLL_OTHERHOST = 3;

	/** The Constant LINUX_SLL_OUTGOING. */
	public final static int LINUX_SLL_OUTGOING = 4;

	/** Constant numerial ID for this protocol's header. */
	public static int ID = JProtocol.SLL_ID;

	/**
	 * Packet type.
	 * 
	 * @return packet type
	 */
	@Field(offset = 0, length = 16)
	public int packetType() {
		return super.getUShort(0);
	}

	/**
	 * Link Layer address type.
	 * 
	 * @return address type
	 */
	@Field(offset = 16, length = 16)
	public int haType() {
		return super.getUShort(2);
	}

	/**
	 * The Enum HardwareAddressType.
	 */
	public enum HardwareAddressType {
		
		/** The LINU x_ sl l_ host. */
		LINUX_SLL_HOST,
		
		/** The LINU x_ sl l_ broadcast. */
		LINUX_SLL_BROADCAST,
		
		/** The LINU x_ sl l_ multicast. */
		LINUX_SLL_MULTICAST,
		
		/** The LINU x_ sl l_ otherhost. */
		LINUX_SLL_OTHERHOST,
		
		/** The LINU x_ sl l_ outgoing. */
		LINUX_SLL_OUTGOING,
	}

	/**
	 * Ha type enum.
	 * 
	 * @return the hardware address type
	 */
	public HardwareAddressType haTypeEnum() {
		return HardwareAddressType.values()[haType()];
	}

	/**
	 * Link Layer address length.
	 * 
	 * @return address length in bytes
	 */
	@Field(offset = 32, length = 16)
	public int haLength() {
		return super.getUShort(4);
	}

	/**
	 * Link Layer address length.
	 * 
	 * @return address length in bits
	 */
	@Dynamic(Field.Property.LENGTH)
	public int addressLength() {
		return haLength() * 8;
	}

	/**
	 * Link layer address.
	 * 
	 * @return address
	 */
	@Field(offset = 48, format = "#mac#")
	public byte[] address() {
		return super.getByteArray(6, haLength());
	}

	/**
	 * next protocol.
	 * 
	 * @return next protocol
	 */
	@Field(offset = 112, length = 16, format = "%x")
	public int type() {
		return super.getUShort(14);
	}

	/**
	 * Next protocol as an EtherType constant.
	 * 
	 * @return next protocol
	 */
	public Ethernet.EthernetType typeEnum() {
		return Ethernet.EthernetType.valueOf(type());
	}
}
