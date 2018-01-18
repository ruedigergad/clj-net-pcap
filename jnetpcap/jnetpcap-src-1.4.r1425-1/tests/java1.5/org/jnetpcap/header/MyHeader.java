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
package org.jnetpcap.header;

import java.util.EnumSet;
import java.util.Set;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JHeaderType;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.BindingVariable;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldSetter;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.BindingVariable.MatchType;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEESnap;
import org.jnetpcap.protocol.network.Ip4;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(name = "ip4", nicname = "ip")
public class MyHeader
    extends JHeaderMap<MyHeader> {

  	/**
  	 * A table of IpTypes and their names
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	public enum Ip4Type implements JHeaderType {
  		/**
  		 * Internet control messaging protocol
  		 */
  		ICMP("icmp", 1),

  		/**
  		 * Ttransmission control protocol
  		 */
  		TCP("tcp", 6),

  		/**
  		 * Unreliable datagram protocol
  		 */
  		UDP("udp", 17), ;
  		/**
  		 * Name of the constant
  		 * 
  		 * @param type
  		 *          ip type number
  		 * @return constants name
  		 */
  		public static String toString(int type) {
  			for (Ip4Type t : values()) {
  				for (int i : t.typeValues) {
  					if (i == type) {
  						return t.description;
  					}
  				}
  			}

  			return Integer.toString(type);
  		}

  		/**
  		 * Converts a numerical type to constant
  		 * 
  		 * @param type
  		 *          Ip4 type number
  		 * @return constant or null if not found
  		 */
  		public static Ip4Type valueOf(int type) {
  			for (Ip4Type t : values()) {
  				for (int i : t.typeValues) {
  					if (i == type) {
  						return t;
  					}
  				}
  			}

  			return null;
  		}

  		/** The description. */
		  private final String description;

  		/** The type values. */
		  private final int[] typeValues;

  		/**
			 * Instantiates a new ip4 type.
			 * 
			 * @param typeValues
			 *          the type values
			 */
		  private Ip4Type(int... typeValues) {
  			this.typeValues = typeValues;
  			this.description = name().toLowerCase();
  		}

  		/**
			 * Instantiates a new ip4 type.
			 * 
			 * @param description
			 *          the description
			 * @param typeValues
			 *          the type values
			 */
		  private Ip4Type(String description, int... typeValues) {
  			this.typeValues = typeValues;
  			this.description = description;

  		}

  		/**
  		 * Description of the type value
  		 * 
  		 * @return description string
  		 */
  		public final String getDescription() {
  			return this.description;
  		}

  		/**
  		 * Converts contant to numerical ip type
  		 * 
  		 * @return Ip4 type number
  		 */
  		public final int[] getTypeValues() {
  			return this.typeValues;
  		}
  	}

  	/**
  	 * Baseclass for all Ip option headers
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	public static abstract class IpOption
  	    extends JSubHeader<Ip4> {

  		/**
  		 * A table of IpOption types and their names
  		 * 
  		 * @author Mark Bednarczyk
  		 * @author Sly Technologies, Inc.
  		 */
  		public enum OptionCode {
  			/* 0 */
  			/** The EN d_ o f_ optio n_ list. */
			  END_OF_OPTION_LIST(0),
  			/* 3 */
  			/** The LOOS e_ sourc e_ route. */
			  LOOSE_SOURCE_ROUTE(3),
  			/* 1 */
  			/** The N o_ op. */
			  NO_OP(1),
  			/* 7 */
  			/** The RECOR d_ route. */
			  RECORD_ROUTE(7),
  			/* 2 */
  			/** The SECURITY. */
			  SECURITY(2),
  			/* 8 */
  			/** The STREA m_ id. */
			  STREAM_ID(8),
  			/* 9 */
  			/** The STRIC t_ sourc e_ route. */
			  STRICT_SOURCE_ROUTE(9),
  			/* 4 */
  			/** The TIMESTAMP. */
			  TIMESTAMP(4),
  			/* 5 */
  			/** The UNASSIGNE d1. */
			  UNASSIGNED1(5),
  			/* 6 */
  			/** The UNASSIGNE d2. */
			  UNASSIGNED2(6),
  			;
  			
			  /** The id. */
			  public final int id;

  			/**
				 * Instantiates a new option code.
				 * 
				 * @param id
				 *          the id
				 */
			  private OptionCode(int id) {
  				this.id = id;				
  			}
  			
  			/**
				 * Value of.
				 * 
				 * @param id
				 *          the id
				 * @return the option code
				 */
			  public static OptionCode valueOf(int id) {
  				for (OptionCode c: values()) {
  					if (c.id == id) {
  						return c;
  					}
  				}
  				
  				return null;
  			}
  		}

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
  			return buffer.getUByte(1);
  		}


  		/**
  		 * Gets the Ip4.code field. Specifies the optional header type.
  		 * <h3>Header Spec</h3>
  		 * <table border=1>
  		 * <tr>
  		 * <td> Protocol Header:</td>
  		 * <td> Ip4</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Protocol Family:</td>
  		 * <td> Networking</td>
  		 * </tr>
  		 * <tr>
  		 * <td> OSI Layer:</td>
  		 * <td> 3</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Field Property:</td>
  		 * <td> constant offset</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Field Offset:</td>
  		 * <td> getUByte(0) & 0x1F</td>
  		 * </tr>
  		 * </table>
  		 * <h3>Header Diagram</h3>
  		 * 
  		 * <pre>
  		 * +------+-----------------+
  		 * | CODE | optional header |
  		 * +------+-----------------+
  		 * </pre>
  		 * 
  		 * @return code field value
  		 */
  		@Field(offset = 0, length = 3, format = "%d")
  		public int code() {
  			return getUByte(0) & 0x1F;
  		}

  		/**
  		 * Sets the Ip4.code field. Specifies the optional header type.
  		 * <h3>Header Spec</h3>
  		 * <table border=1>
  		 * <tr>
  		 * <td> Protocol Header:</td>
  		 * <td> Ip4</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Protocol Family:</td>
  		 * <td> Networking</td>
  		 * </tr>
  		 * <tr>
  		 * <td> OSI Layer:</td>
  		 * <td> 3</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Field Property:</td>
  		 * <td> constant offset</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Field Offset:</td>
  		 * <td> getUByte(0) & 0x1F</td>
  		 * </tr>
  		 * </table>
  		 * <h3>Header Diagram</h3>
  		 * 
  		 * <pre>
  		 * +------+-----------------+
  		 * | CODE | optional header |
  		 * +------+-----------------+
  		 * </pre>
  		 * 
  		 * @param value
  		 *          new code value
  		 */
  		@FieldSetter
  		public void code(int value) {
  			setUByte(0, code() & 0xE0 | value & 0x1F);
  		}

  		/**
  		 * Gets the Ip4.code field. Specifies the optional header type.
  		 * <h3>Header Spec</h3>
  		 * <table border=1>
  		 * <tr>
  		 * <td> Protocol Header:</td>
  		 * <td> Ip4</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Protocol Family:</td>
  		 * <td> Networking</td>
  		 * </tr>
  		 * <tr>
  		 * <td> OSI Layer:</td>
  		 * <td> 3</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Field Property:</td>
  		 * <td> constant offset</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Field Offset:</td>
  		 * <td> getUByte(0) & 0x1F</td>
  		 * </tr>
  		 * </table>
  		 * <h3>Header Diagram</h3>
  		 * 
  		 * <pre>
  		 * +------+-----------------+
  		 * | CODE | optional header |
  		 * +------+-----------------+
  		 * </pre>
  		 * 
  		 * @return code field value
  		 */
  		public OptionCode codeEnum() {
  			return OptionCode.values()[getUByte(0) & 0x1F];
  		}

  		/**
  		 * Sets the Ip4.code field. Specifies the optional header type.
  		 * <h3>Header Spec</h3>
  		 * <table border=1>
  		 * <tr>
  		 * <td> Protocol Header:</td>
  		 * <td> Ip4</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Protocol Family:</td>
  		 * <td> Networking</td>
  		 * </tr>
  		 * <tr>
  		 * <td> OSI Layer:</td>
  		 * <td> 3</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Field Property:</td>
  		 * <td> constant offset</td>
  		 * </tr>
  		 * <tr>
  		 * <td> Field Offset:</td>
  		 * <td> getUByte(0) & 0x1F</td>
  		 * </tr>
  		 * </table>
  		 * <h3>Header Diagram</h3>
  		 * 
  		 * <pre>
  		 * +------+-----------------+
  		 * | CODE | optional header |
  		 * +------+-----------------+
  		 * </pre>
  		 * 
  		 * @param value
  		 *          new code value
  		 */
  		public void optionCode(OptionCode value) {
  			code(value.ordinal());
  		}
  	}

  	/**
  	 * Ip4 optional Loose Source Route header
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	@Header(id=3)
  	public static class LooseSourceRoute
  	    extends Routing {
  	}

  	/**
  	 * Ip4 optional No Operation header. Takes up exactly 1 byte of memory.
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	@Header(id=1)
  	public static class NoOp
  	    extends IpOption {
  	}

  	/**
  	 * Ip4 optional Record Route header
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	@Header(id=7)
  	public static class RecordRoute
  	    extends Routing {
  	}

  	/**
  	 * Ip4 optional Routing header
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	public static abstract class Routing
  	    extends IpOption {

  		/**
			 * Address.
			 * 
			 * @param values
			 *          the values
			 */
		  @FieldSetter
  		public void address(byte[][] values) {
  			for (int i = 0; i < values.length; i++) {
  				address(i, values[i]);
  			}
  		}

  		/**
			 * Address.
			 * 
			 * @param index
			 *          the index
			 * @return the byte[]
			 */
		  public byte[] address(int index) {
  			return getByteArray(index * 4 + 3, 4);
  		}

  		/**
			 * Address.
			 * 
			 * @param index
			 *          the index
			 * @param value
			 *          the value
			 */
		  public void address(int index, byte[] value) {
  			setByteArray(index * 4 + 3, value);
  		}

  		/**
			 * Address array.
			 * 
			 * @return the byte[][]
			 */
		  @Field(offset = 24, length=0, format = "#ip4[]#")
  		public byte[][] addressArray() {

  			byte[][] ba = new byte[addressCount()][];

  			for (int i = 0; i < addressCount(); i++) {
  				ba[i] = address(i);
  			}

  			return ba;
  		}

  		/**
			 * Address count.
			 * 
			 * @return the int
			 */
		  public int addressCount() {
  			return (length() - 3) / 4;
  		}

  		/**
			 * Length.
			 * 
			 * @return the int
			 */
		  @Field(offset = 8, length = 8)
  		public int length() {
  			return getUByte(1);
  		}

  		/**
			 * Length.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void length(int value) {
  			setUByte(1, value);
  		}

  		/**
			 * Length description.
			 * 
			 * @return the string
			 */
		  @Dynamic(Field.Property.DESCRIPTION)
  		public String lengthDescription() {
  			return "(" + length() + " - 3)/" + 4 + " = " + addressCount() + " routes";
  		}

  		/**
			 * Offset.
			 * 
			 * @return the int
			 */
		  @Field(offset = 16, length = 8)
  		public int offset() {
  			return getUByte(2);
  		}

  		/**
			 * Offset.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void offset(int value) {
  			setUByte(2, value);
  		}

  		/**
			 * Offset description.
			 * 
			 * @return the string
			 */
		  @Dynamic(Field.Property.DESCRIPTION)
  		public String offsetDescription() {
  			return "offset points at route #" + (offset() / 4 - 1) + "";
  		}
  	}

  	/**
  	 * Ip4 optional Security header.
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	@Header(id=2)
  	public static class Security
  	    extends IpOption {

  		/**
  		 * A table of security algorithm types
  		 * 
  		 * @author Mark Bednarczyk
  		 * @author Sly Technologies, Inc.
  		 */
  		public enum SecurityType {
  			
			  /** The CONFIDENTIAL. */
			  CONFIDENTIAL(61749),
  			
			  /** The EFTO. */
			  EFTO(30874),
  			
			  /** The MMMM. */
			  MMMM(48205),
  			
			  /** The PROG. */
			  PROG(24102),
  			
			  /** The RESTRICTED. */
			  RESTRICTED(44819),
  			
			  /** The SECRET. */
			  SECRET(55176),
  			
			  /** The UNCLASSIFIED. */
			  UNCLASSIFIED(0)

  			;
  			
			  /**
				 * Value of.
				 * 
				 * @param type
				 *          the type
				 * @return the security type
				 */
			  public static SecurityType valueOf(int type) {
  				for (SecurityType t : values()) {
  					if (t.getType() == type) {
  						return t;
  					}
  				}

  				return null;
  			}

  			/** The type. */
			  private final int type;

  			/**
				 * Instantiates a new security type.
				 * 
				 * @param type
				 *          the type
				 */
			  private SecurityType(int type) {
  				this.type = type;

  			}

  			/**
				 * Gets the type.
				 * 
				 * @return the type
				 */
  			public final int getType() {
  				return this.type;
  			}
  		}

  		/**
			 * Compartments.
			 * 
			 * @return the int
			 */
		  @Field(offset = 4 * 8, length = 16)
  		public int compartments() {
  			return getUShort(4);
  		}

  		/**
			 * Compartments.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void compartments(int value) {
  			setUShort(4, value);
  		}

  		/**
			 * Control.
			 * 
			 * @return the int
			 */
		  @Field(offset = 8 * 8, length = 24)
  		public int control() {
  			return (int) (getUShort(8) << 8) | getUByte(10); // 24 bits in
  			// BIG_E
  		}

  		/**
			 * Control.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void control(int value) {
  			// TODO: implement Ip4.Security.control field setter
  			throw new UnsupportedOperationException("Not implemented yet");
  		}

  		/**
			 * Handling.
			 * 
			 * @return the int
			 */
		  @Field(offset = 6 * 8, length = 16)
  		public int handling() {
  			return getUShort(6);
  		}

  		/**
			 * Length.
			 * 
			 * @return the int
			 */
		  @Field(offset = 8, length = 8)
  		public int length() {
  			return getUByte(1);
  		}

  		/**
			 * Length.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void length(int value) {
  			setUByte(1, value);
  		}

  		/**
			 * Security.
			 * 
			 * @return the int
			 */
		  @Field(offset = 16, length = 16)
  		public int security() {
  			return getUShort(2);
  		}

  		/**
			 * Security.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void security(int value) {
  			setUShort(2, value);
  		}

  		/**
			 * Security.
			 * 
			 * @param value
			 *          the value
			 */
		  public void security(SecurityType value) {
  			security(value.type);
  		}

  		/**
			 * Security enum.
			 * 
			 * @return the security type
			 */
		  public SecurityType securityEnum() {
  			return SecurityType.valueOf(security());
  		}
  	}

  	/**
  	 * Ip4 optional Stream ID header
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	@Header(id=8)
  	public static class StreamId
  	    extends IpOption {

  		/**
			 * Length.
			 * 
			 * @return the int
			 */
		  @Field(offset = 8, length = 8)
  		public int length() {
  			return getUByte(1);
  		}

  		/**
			 * Length.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void length(int value) {
  			setUByte(1, value);
  		}

  		/**
			 * Stream id.
			 * 
			 * @return the int
			 */
		  @Field(offset = 16, length = 16, format = "%x")
  		public int streamId() {
  			return getUShort(2);
  		}

  		/**
			 * Stream id.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void streamId(int value) {
  			setUShort(2, value);
  		}
  	}

  	/**
  	 * Ip4 optional Strict Source Route header
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	@Header(id=9)
  	public static class StrictSourceRoute
  	    extends Routing {
  	};

  	/**
  	 * Ip4 optional Timestamp header
  	 * 
  	 * @author Mark Bednarczyk
  	 * @author Sly Technologies, Inc.
  	 */
  	@Header(id=4)
  	public static class Timestamp
  	    extends IpOption {
  		
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
  			return buffer.getUByte(1);
  		}

  		/**
  		 * Ip4 optional Timestamp header - a timestamp entry
  		 * 
  		 * @author Mark Bednarczyk
  		 * @author Sly Technologies, Inc.
  		 */
  		public static class Entry {
  			
			  /** The address. */
			  public byte[] address;

  			/** The timestamp. */
			  public long timestamp;
  		}

  		/**
  		 * A table of Ip4 Timestamp header flags
  		 * 
  		 * @author Mark Bednarczyk
  		 * @author Sly Technologies, Inc.
  		 */
  		public enum Flag {
  			
			  /** The TIMESTAM p_ wit h_ ip. */
			  TIMESTAMP_WITH_IP,
  			
			  /** The TIMESTAMP s_ prespecified. */
			  TIMESTAMPS_PRESPECIFIED
  		}

  		/** The Constant FLAG_TIMESTAMP_WITH_IP. */
		  public final static int FLAG_TIMESTAMP_WITH_IP = 0x01;

  		/** The Constant FLAG_TIMESTAMPS_PRESPECIFIED. */
		  public final static int FLAG_TIMESTAMPS_PRESPECIFIED = 0x2;

  		/** The Constant MASK_FLAGS. */
		  public final static int MASK_FLAGS = 0x0F;

  		/** The Constant MASK_OVERFLOW. */
		  public final static int MASK_OVERFLOW = 0xF0;

  		/**
			 * Address.
			 * 
			 * @param index
			 *          the index
			 * @return the byte[]
			 */
		  public byte[] address(int index) {
  			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
  				return null;

  			} else {
  				return getByteArray(index * 4 + 4, 4);
  			}
  		}
  		
  		/**
			 * Entries length.
			 * 
			 * @return the int
			 */
		  @Dynamic(Field.Property.LENGTH)
  		public int entriesLength() {
  			return (length() -4) * 8;
  		}

  		/**
			 * Entries.
			 * 
			 * @return the entry[]
			 */
		  @Field(offset = 4 * 8, format="%s")
  		public Entry[] entries() {
  			final int flags = flags();

  			if ((flags & FLAG_TIMESTAMP_WITH_IP) == 0) {
  				return entriesTimestampOnly();

  			} else {
  				return entriesWithIp();
  			}
  		}

  		/**
			 * Entries timestamp only.
			 * 
			 * @return the entry[]
			 */
		  private Entry[] entriesTimestampOnly() {
  			final int length = length() - 4;
  			final Entry[] entries = new Entry[length / 4];

  			for (int i = 4; i < length; i += 8) {
  				final Entry entry = entries[i / 8];
  				entry.address = getByteArray(i, 4);
  				entry.timestamp = getUInt(i + 4);
  			}

  			return entries;
  		}

  		/**
			 * Entries with ip.
			 * 
			 * @return the entry[]
			 */
		  private Entry[] entriesWithIp() {
  			final int length = length() - 4;
  			final Entry[] entries = new Entry[length / 4];

  			for (int i = 4; i < length; i += 4) {
  				final Entry entry = entries[i / 4];
  				entry.timestamp = getUInt(i + 4);
  			}

  			return entries;
  		}

  		/**
			 * Flags.
			 * 
			 * @return the int
			 */
		  @Field(offset = 3 * 8 + 4, length = 4)
  		public int flags() {
  			return (getUByte(3) & MASK_FLAGS);
  		}

  		/**
			 * Flags.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void flags(int value) {
  			setUByte(3, value & MASK_FLAGS);
  		}

  		/**
			 * Flags enum.
			 * 
			 * @return the sets the
			 */
		  public Set<Flag> flagsEnum() {
  			final Set<Flag> r = EnumSet.noneOf(Flag.class);
  			int flags = flags();

  			if ((flags & FLAG_TIMESTAMP_WITH_IP) == FLAG_TIMESTAMP_WITH_IP) {
  				r.add(Flag.TIMESTAMP_WITH_IP);
  			}

  			if ((flags & FLAG_TIMESTAMPS_PRESPECIFIED) == FLAG_TIMESTAMPS_PRESPECIFIED) {
  				r.add(Flag.TIMESTAMPS_PRESPECIFIED);
  			}

  			return r;
  		}

  		/**
			 * Length.
			 * 
			 * @return the int
			 */
		  @Field(offset = 1 * 8, length = 8)
  		public int length() {
  			return getUByte(1);
  		}

  		/**
			 * Length.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void length(int value) {
  			setUByte(1, value);
  		}

  		/**
			 * Offset.
			 * 
			 * @return the int
			 */
		  @Field(offset = 2 * 8, length = 16)
  		public int offset() {
  			return getUByte(2);
  		}

  		/**
			 * Offset.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void offset(int value) {
  			setUByte(2, value);
  		}

  		/**
			 * Overflow.
			 * 
			 * @return the int
			 */
		  @Field(offset = 3 * 8, length = 4)
  		public int overflow() {
  			return (getUByte(3) & MASK_OVERFLOW) >> 4;
  		}

  		/**
			 * Overflow.
			 * 
			 * @param value
			 *          the value
			 */
		  @FieldSetter
  		public void overflow(int value) {
  			setUByte(3, value << 4 | flags());
  		}

  		/**
			 * Timestamp.
			 * 
			 * @param index
			 *          the index
			 * @return the long
			 */
		  public long timestamp(int index) {
  			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
  				return getUInt(index * 4 + 4);

  			} else {
  				return getUInt(index * 4 + 8);
  			}
  		}

  		/**
			 * Timestamps count.
			 * 
			 * @return the int
			 */
		  public int timestampsCount() {
  			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
  				return (length() - 4) / 4;

  			} else {
  				return (length() - 4) / 8;
  			}
  		}
  	}

  	/** The Constant DIFF_CODEPOINT. */
	  public final static int DIFF_CODEPOINT = 0xFC;

  	/** The Constant DIFF_ECE. */
	  public final static int DIFF_ECE = 0x01;

  	/** The Constant DIFF_ECT. */
	  public final static int DIFF_ECT = 0x02;

  	/** The Constant FLAG_DONT_FRAGMENT. */
	  public final static int FLAG_DONT_FRAGMENT = 0x2;

  	/** The Constant FLAG_MORE_FRAGMENTS. */
	  public final static int FLAG_MORE_FRAGMENTS = 0x1;

  	/** The Constant FLAG_RESERVED. */
	  public final static int FLAG_RESERVED = 0x4;
  	
  	/** The Constant ID. */
	  public final static int ID = JProtocol.IP4_ID;

  	/**
		 * Bind to ethernet.
		 * 
		 * @param packet
		 *          the packet
		 * @param eth
		 *          the eth
		 * @return true, if successful
		 */
	  @Bind(to = Ethernet.class)
  	public static boolean bindToEthernet(JPacket packet, Ethernet eth) {
  		return eth.type() == 0x800;
  	}

  	/**
		 * Bind to snap.
		 * 
		 * @param packet
		 *          the packet
		 * @param snap
		 *          the snap
		 * @return true, if successful
		 */
	  @Bind(to = IEEESnap.class)
  	public static boolean bindToSnap(JPacket packet, IEEESnap snap) {
  		return snap.pid() == 0x800;
  	}

  	/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
	  @HeaderLength
  	public static int getHeaderLength(JBuffer buffer, int offset) {
  		return (buffer.getUByte(offset) & 0x0F) * 4;
  	}

  	/** The hashcode. */
	  private int hashcode;

  	/**
		 * Checksum.
		 * 
		 * @return the int
		 */
	  @Field(offset = 10 * 8, length = 16, format = "%x")
  	public int checksum() {
  		return getUShort(10);
  	}

  	/**
		 * Checksum.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void checksum(int value) {
  		setUShort(10, value);
  	}

  	/**
		 * Check type.
		 * 
		 * @param type
		 *          the type
		 * @return true, if successful
		 */
	  @BindingVariable(MatchType.FUNCTION)
  	public boolean checkType(int type) {
  		return type() == type && offset() == 0;
  	}

  	/**
		 * Clear flags.
		 * 
		 * @param flags
		 *          the flags
		 */
	  public void clearFlags(int flags) {
  		int o = getUByte(6);
  		o &= ~(flags << 5);

  		setUByte(6, o);
  	}

  	/*
  	 * (non-Javadoc)
  	 * 
  	 * @see org.jnetpcap.packet.JHeaderMap#decodeUniqueSubHeaders()
  	 */
  	@Override
  	protected void decodeHeader() {
  		optionsBitmap = 0;
  		this.hashcode = (id() << 16) ^ sourceToInt() ^ destinationToInt() ^ type();

  		System.out.printf("offset=%d, %s", getOffset(), toHexdump());
  		final int hlen = hlen() * 4;

  		for (int i = 20; i < hlen; i++) {
  			final int id = getUByte(i) & 0x1F;
  			optionsOffsets[id] = i;
  			optionsBitmap |= (1 << id);

  			switch (IpOption.OptionCode.valueOf(id)) {
  				case NO_OP:
  					optionsLength[id] = 1;
  					break;

  				case END_OF_OPTION_LIST:
  					optionsLength[id] = hlen - i;
  					i = hlen;
  					break;

  				default:
  					final int length = getUByte(i + 1); // Length option field
  					i += length;
  					optionsLength[id] = length;
  					break;
  			}

  			System.out.printf("i=%d id=%d bitmap=0x%X length=%d\n", i, id,
  			    optionsBitmap, optionsLength[id]);
  		}
  	}

  	/**
		 * Destination.
		 * 
		 * @return the byte[]
		 */
	  @Field(offset = 16 * 8, length = 32, format = "#ip4#")
  	public byte[] destination() {
  		return getByteArray(16, 4);
  	}

  	/**
		 * Destination.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void destination(byte[] value) {
  		setByteArray(12, value);
  	}

  	/**
		 * Destination to byte array.
		 * 
		 * @param address
		 *          the address
		 * @return the byte[]
		 */
	  public byte[] destinationToByteArray(byte[] address) {
  		if (address.length != 4) {
  			throw new IllegalArgumentException("address must be 4 byte long");
  		}
  		return getByteArray(16, address);
  	}

  	/**
		 * Destination to int.
		 * 
		 * @return the int
		 */
	  public int destinationToInt() {
  		return getInt(16);
  	}

  	/**
		 * Flags.
		 * 
		 * @return the int
		 */
	  @Field(offset = 6 * 8, length = 3, format = "%x")
  	public int flags() {
  		return getUByte(6) >> 5;
  	}

  	/**
		 * Flags.
		 * 
		 * @param flags
		 *          the flags
		 */
	  @FieldSetter
  	public void flags(int flags) {
  		int o = getUByte(6) & 0x1F;
  		o |= flags << 5;

  		setUByte(6, o);
  	}

  	/**
		 * Flags_ df.
		 * 
		 * @return the int
		 */
	  @Field(parent = "flags", offset = 1, length = 1, display = "do not fragment")
  	public int flags_DF() {
  		return (flags() & FLAG_DONT_FRAGMENT) >> 1;
  	}

  	/**
		 * Flags_ df description.
		 * 
		 * @return the string
		 */
	  @Dynamic(Field.Property.DESCRIPTION)
  	public String flags_DFDescription() {
  		return (flags_DF() > 0) ? "set" : "not set";
  	}

  	/**
		 * Flags_ mf.
		 * 
		 * @return the int
		 */
	  @Field(parent = "flags", offset = 0, length = 1, display = "more fragments", nicname = "M")
  	public int flags_MF() {
  		return (flags() & FLAG_MORE_FRAGMENTS) >> 2;
  	}

  	/**
		 * Flags_ mf description.
		 * 
		 * @return the string
		 */
	  @Dynamic(Field.Property.DESCRIPTION)
  	public String flags_MFDescription() {
  		return (flags_MF() > 0) ? "set" : "not set";
  	}

  	/* (non-Javadoc)
	   * @see java.lang.Object#hashCode()
	   */
	  @Override
  	public int hashCode() {
  		return this.hashcode;
  	}

  	/**
		 * Hlen.
		 * 
		 * @return the int
		 */
	  @Field(offset = 0 * 8 + 4, length = 4, format = "%d")
  	public int hlen() {
  		return getUByte(0) & 0x0F;
  	}

  	/**
		 * Hlen.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void hlen(int value) {
  		int o = getUByte(0) & 0xF0;
  		o |= value & 0x0F;

  		setUByte(0, o);
  	}

  	/**
		 * Hlen description.
		 * 
		 * @return the string
		 */
	  @Dynamic(Field.Property.DESCRIPTION)
  	public String hlenDescription() {
  		String pre = "" + hlen() + " * 4 = " + (hlen() * 4) + " bytes";
  		return (hlen() == 5) ? pre + ", No Ip Options" : pre
  		    + ", Ip Options Present";
  	}

  	/**
		 * Id.
		 * 
		 * @return the int
		 */
	  @Field(offset = 4 * 8, length = 16, format = "%x")
  	public int id() {
  		return getUShort(4);
  	}

  	/**
		 * Id.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void id(int value) {
  		setUShort(4, value);
  	}

  	/**
		 * Length.
		 * 
		 * @return the int
		 */
	  @Field(offset = 2 * 8, length = 16, format = "%d")
  	public int length() {
  		return getUShort(2);
  	}

  	/**
		 * Length.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void length(int value) {
  		setUShort(2, value);
  	}

  	/**
		 * Offset.
		 * 
		 * @return the int
		 */
	  @Field(offset = 6 * 8 + 3, length = 13, format = "%d")
  	public int offset() {
  		return getUShort(6) & 0x1FFF;
  	}

  	/**
		 * Offset.
		 * 
		 * @param offset
		 *          the offset
		 */
	  @FieldSetter
  	public void offset(int offset) {
  		int o = getUShort(6) & ~0x1FFF;
  		o |= offset & 0x1FFF;

  		setUShort(6, o);
  	}

  	/**
		 * Source.
		 * 
		 * @return the byte[]
		 */
	  @Field(offset = 12 * 8, length = 32, format = "#ip4#")
  	public byte[] source() {
  		return getByteArray(12, 4);
  	}

  	/**
		 * Source.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void source(byte[] value) {
  		setByteArray(12, value);
  	}

  	/**
		 * Source to byte array.
		 * 
		 * @param address
		 *          the address
		 * @return the byte[]
		 */
	  public byte[] sourceToByteArray(byte[] address) {
  		if (address.length != 4) {
  			throw new IllegalArgumentException("address must be 4 byte long");
  		}
  		return getByteArray(12, address);
  	}

  	/**
		 * Source to int.
		 * 
		 * @return the int
		 */
	  public int sourceToInt() {
  		return getInt(12);
  	}

  	/**
		 * Tos.
		 * 
		 * @return the int
		 */
	  @Field(offset = 1 * 8, length = 8, format = "%x", display = "diffserv")
  	public int tos() {
  		return getUByte(1);
  	}

  	/**
		 * Tos.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void tos(int value) {
  		setUByte(1, value);
  	}

  	/**
		 * Tos_ codepoint.
		 * 
		 * @return the int
		 */
	  @Field(parent = "tos", offset = 2, length = 6, display = "code point")
  	public int tos_Codepoint() {
  		return (tos() & DIFF_CODEPOINT) >> 2;
  	}

  	/**
		 * Tos_ codepoint description.
		 * 
		 * @return the string
		 */
	  @Dynamic(Field.Property.DESCRIPTION)
  	public String tos_CodepointDescription() {
  		return (tos_Codepoint() > 0) ? "code point " + tos_Codepoint() : "not set";
  	}

  	/**
		 * Tos_ ece.
		 * 
		 * @return the int
		 */
	  @Field(parent = "tos", offset = 0, length = 1, display = "ECE bit")
  	public int tos_ECE() {
  		return (tos() & DIFF_ECE) >> 0;
  	}

  	/**
		 * Tos_ ece description.
		 * 
		 * @return the string
		 */
	  @Dynamic(Field.Property.DESCRIPTION)
  	public String tos_ECEDescription() {
  		return (tos_ECE() > 0) ? "set" : "not set";
  	}

  	/**
		 * Tos_ ecn.
		 * 
		 * @return the int
		 */
	  @Field(parent = "tos", offset = 1, length = 1, display = "ECN bit")
  	public int tos_ECN() {
  		return (tos() & DIFF_ECT) >> 1;
  	}

  	/**
		 * Tos_ ecn description.
		 * 
		 * @return the string
		 */
	  @Dynamic(Field.Property.DESCRIPTION)
  	public String tos_ECNDescription() {
  		return (tos_ECN() > 0) ? "set" : "not set";
  	}

  	/**
		 * Ttl.
		 * 
		 * @return the int
		 */
	  @Field(offset = 8 * 8, length = 8, format = "%d", description = "time to live")
  	public int ttl() {
  		return getUByte(8);
  	}

  	/**
		 * Ttl.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void ttl(int value) {
  		setUByte(8, value);
  	}

  	/**
		 * Type.
		 * 
		 * @return the int
		 */
	  @Field(offset = 9 * 8, length = 8, format = "%d")
  	public int type() {
  		return getUByte(9);
  	}

  	/**
		 * Type.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void type(int value) {
  		setUByte(9, value);
  	}

  	/**
		 * Type.
		 * 
		 * @param type
		 *          the type
		 */
	  public void type(Ip4Type type) {
  		setUByte(9, type.typeValues[0]);
  	}

  	/**
		 * Type description.
		 * 
		 * @return the string
		 */
	  @Dynamic(Field.Property.DESCRIPTION)
  	public String typeDescription() {
  		return "next: " + Ip4Type.toString(type());
  	}

  	/**
		 * Type enum.
		 * 
		 * @return the ip4 type
		 */
	  public Ip4Type typeEnum() {
  		return Ip4Type.valueOf(type());
  	}

  	/**
		 * Version.
		 * 
		 * @return the int
		 */
	  @Field(offset = 0 * 8 + 0, length = 4, format = "%d")
  	public int version() {
  		return getUByte(0) >> 4;
  	}

  	/**
		 * Version.
		 * 
		 * @param value
		 *          the value
		 */
	  @FieldSetter
  	public void version(int value) {
  		setUByte(0, hlen() | value << 4);
  	}


}
