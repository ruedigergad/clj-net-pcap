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

import java.nio.ByteOrder;
import java.util.List;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Format;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.Header.Characteristic;
import org.jnetpcap.packet.annotate.Header.Layer;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.checksum.Checksum;

/**
 * Ethernet2 definition. Datalink layer ethernet frame definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 14, dlt = {
		PcapDLT.EN10MB,
		PcapDLT.FDDI
}, suite = ProtocolSuite.LAN, osi = Layer.DATALINK, characteristics = Characteristic.CSMA_CD, nicname = "Eth", description = "Ethernet", url = "http://en.wikipedia.org/wiki/Ethernet")
public class Ethernet extends JHeader implements JHeaderChecksum {

	/**
	 * A table of EtherType values and their names.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum EthernetType {

		/** The IEE e_802 do t1 q. */
		IEEE_802DOT1Q(0x8100, "vlan - IEEE 802.1q"),
		/** The I p4. */
		IP4(0x800, "ip version 4"),
		/** The I p6. */
		IP6(0x86DD, "ip version 6"), ;

		/**
		 * To string.
		 * 
		 * @param id
		 *          the id
		 * @return the string
		 */
		public static String toString(int id) {
			for (EthernetType t : values()) {
				if (t.id == id) {
					return t.description;
				}
			}

			return null;
		}

		/**
		 * Value of.
		 * 
		 * @param type
		 *          the type
		 * @return the ethernet type
		 */
		public static EthernetType valueOf(int type) {
			for (EthernetType t : values()) {
				if (t.id == type) {
					return t;
				}
			}

			return null;
		}

		/** The description. */
		private final String description;

		/** The id. */
		private final int id;

		/**
		 * Instantiates a new ethernet type.
		 * 
		 * @param id
		 *          the id
		 */
		private EthernetType(int id) {
			this.id = id;
			this.description = name().toLowerCase();
		}

		/**
		 * Instantiates a new ethernet type.
		 * 
		 * @param id
		 *          the id
		 * @param description
		 *          the description
		 */
		private EthernetType(int id, String description) {
			this.id = id;
			this.description = description;

		}

		/**
		 * Gets the description.
		 * 
		 * @return the description
		 */
		public final String getDescription() {
			return this.description;
		}

		/**
		 * Gets the id.
		 * 
		 * @return the id
		 */
		public final int getId() {
			return this.id;
		}

	}

	/** The Constant ADDRESS_IG_BIT. */
	public static final int ADDRESS_IG_BIT = 0x40;

	/** The Constant ADDRESS_LG_BIT. */
	public static final int ADDRESS_LG_BIT = 0x80;

	/** The Constant ID. */
	public static final int ID = JProtocol.ETHERNET_ID;

	/** The Constant LENGTH. */
	public static final int LENGTH = 14; // Ethernet header is 14 bytes long

	/** The Constant ORG_IEEE. */
	public static final String ORG_IEEE = "IEEE Ethernet2";

	/**
	 * Calculate checksum.
	 * 
	 * @return the long
	 */
	public int calculateChecksum() {
		if (getPostfixLength() < 4) {
			return 0;
		}

		final JPacket packet = getPacket();
		return Checksum.crc32IEEE802(packet, 0, getHeaderLength()
				+ getPayloadLength() + getPostfixLength() -4);
	}

	/**
	 * Retrieves the header's checksum.
	 * 
	 * @return header's stored checksum
	 */
	@Field(length = 4 * BYTE, format = "%x", display = "FCS")
	public int checksum() {
		if (getPostfixLength() < 4) {
			return 0;
		}

		final JPacket packet = getPacket();
		packet.order(ByteOrder.BIG_ENDIAN);
		return packet.getInt(packet.size() - 4);
	}

	/**
	 * Sets the checksum, Ethernet.FCS field in the last 4 bytes of the packet
	 * buffer, which is also the Ethernet trailer part or jNetPcap 'postfix'. The
	 * method checks if last 4 bytes are actually part of physical Ethernet
	 * trailer. If not, the method returns without an error, but FCS is not set.
	 * 
	 * @param crc
	 *          the crc
	 * @return true if checksum was set, otherwise if Ethernet trailer part or
	 *         Ethernet postfix part is less then 4 bytes long, returns false
	 */
	public boolean checksum(int crc) {
		if (getPostfixLength() < 4) {
			return false;
		}

		final JPacket packet = getPacket();
		packet.order(ByteOrder.BIG_ENDIAN);

		packet.setUInt(packet.size() - 4, crc);

		return true;
	}

	/**
	 * Checks if FCS is available for this Ethernet frame. FCS is typically
	 * stripped by the OS and not provided to Libpcap/jNetPcap on most platforms.
	 * 
	 * @return true if FCS is present, otherwise false
	 */
	@Dynamic(field = "checksum", value = Field.Property.CHECK)
	public boolean checksumCheck() {
		return getPostfixLength() >= 4 && checksum() != 0;
	}

	/**
	 * Checksum description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {
		final int crc32 = calculateChecksum();
		if (checksum() == crc32) {
			return "correct";
		} else {
			return "incorrect: 0x" + Long.toHexString(crc32 & 0xFFFFFFFF).toUpperCase();
		}
	}

	/**
	 * Calculates the offset of the FCS field within the Ethernet frame.
	 * 
	 * @return offset, in bits, from the start of the packet buffer
	 */
	@Dynamic(Field.Property.OFFSET)
	public int checksumOffset() {
		return getPostfixOffset() * BYTE;
	}

	/**
	 * Destination.
	 * 
	 * @return the byte[]
	 */
	@Field(offset = 0 * BYTE, length = 6 * BYTE, format = "#mac#", mask = 0xFFFF00000000L)
	public byte[] destination() {
		return getByteArray(0, 6);
	}

	/**
	 * Destination.
	 * 
	 * @param array
	 *          the array
	 */
	public void destination(byte[] array) {
		setByteArray(0, array);
	}

	/**
	 * Destination_ ig.
	 * 
	 * @return the long
	 */
	@Field(parent = "destination", offset = 48 - 8, length = 1, display = "IG bit")
	@FlowKey(index = 0)
	public long destination_IG() {
		return (getUByte(0) & ADDRESS_IG_BIT) >> 5;
	}

	/**
	 * Destination_ lg.
	 * 
	 * @return the long
	 */
	@Field(parent = "destination", offset = 48 - 7, length = 1, display = "LG bit")
	public long destination_LG() {
		return (getUByte(0) & ADDRESS_LG_BIT) >> 6;
	}

	/**
	 * Destination to byte array.
	 * 
	 * @param array
	 *          the array
	 * @return the byte[]
	 */
	public byte[] destinationToByteArray(byte[] array) {
		return getByteArray(0, array);
	}

	/**
	 * Format header.
	 * 
	 * @param fields
	 *          the fields
	 */
	@Format
	public void formatHeader(List<JField> fields) {

	}

	/**
	 * @return
	 * @see org.jnetpcap.packet.JHeaderChecksum#isChecksumValid()
	 */
	@Override
	public boolean isChecksumValid() {
		if (getPostfixLength() < 4 && checksum() != 0) {
			return true;
		}

		return checksum() == calculateChecksum();
	}

	/**
	 * Method which recomputes the checksum and sets the new computed value in
	 * checksum field.
	 * 
	 * @return true if setter succeeded, or false if unable to set the checksum
	 *         such as when its the case when header is truncated or not complete
	 * @see org.jnetpcap.packet.JHeaderChecksum#recalculateChecksum()
	 */
	@Override
	public boolean recalculateChecksum() {
		return checksum(calculateChecksum());
	}

	/**
	 * Source.
	 * 
	 * @return the byte[]
	 */
	@Field(offset = 6 * BYTE, length = 6 * BYTE, format = "#mac#", mask = 0xFFFF00000000L)
	@FlowKey(index = 0)
	public byte[] source() {
		return getByteArray(0 + 6, 6);
	}

	/**
	 * Source.
	 * 
	 * @param array
	 *          the array
	 */
	public void source(byte[] array) {
		setByteArray(0 + 6, array);
	}

	/**
	 * Source_ ig.
	 * 
	 * @return the long
	 */
	@Field(parent = "source", offset = 6 * BYTE - 8, length = 1, display = "IG bit")
	public long source_IG() {
		return (getUByte(0) & ADDRESS_IG_BIT) >> 5;
	}

	/**
	 * Source_ lg.
	 * 
	 * @return the long
	 */
	@Field(parent = "source", offset = 6 * BYTE - 7, length = 1, display = "LG bit")
	public long source_LG() {
		return (getUByte(0) & ADDRESS_LG_BIT) >> 6;
	}

	/**
	 * Source to byte array.
	 * 
	 * @param array
	 *          the array
	 * @return the byte[]
	 */
	public byte[] sourceToByteArray(byte[] array) {
		return getByteArray(0 + 6, array);
	}

	/**
	 * Type.
	 * 
	 * @return the int
	 */
	@Field(offset = 12 * BYTE, length = 2 * BYTE, format = "%x")
	@FlowKey(index = 1)
	public int type() {
		return getUShort(0 + 12);
	}

	/**
	 * Type.
	 * 
	 * @param type
	 *          the type
	 */
	public void type(int type) {
		setUShort(0 + 12, type);
	}

	/**
	 * Type description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String typeDescription() {
		return EthernetType.toString(type());
	}

	/**
	 * Type enum.
	 * 
	 * @return the ethernet type
	 */
	public EthernetType typeEnum() {
		return EthernetType.valueOf(type());
	}

}
