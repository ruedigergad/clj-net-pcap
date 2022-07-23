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

import java.util.EnumSet;
import java.util.Set;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JHeaderType;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.BindingVariable;
import org.jnetpcap.packet.annotate.BindingVariable.MatchType;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldSetter;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.Header.Layer;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.Protocol;
import org.jnetpcap.packet.annotate.Protocol.Suite;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.checksum.Checksum;

// TODO: Auto-generated Javadoc
/**
 * IP version 4. Network layer internet protocol version 4. This is the main
 * header file for Internet Protocol version 4. The header file defines various
 * accessor methods for reading directly out of the Ip4 data structure found
 * within the packet data buffer. The header is peered with the packet at
 * appropriate offset into the buffer and data can be accessed via friendly
 * accessor methods defined by this header, or by using JBuffer accessors. The
 * header also performs decoding of the header, sepecifically decoding and
 * attaching optional sub-headers to this header.
 * <p>
 * Ip4 header is the backbone of the internet.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Protocol(suite = Suite.NETWORK)
@Header(name = "Ip4", nicname = "Ip", osi = Layer.NETWORK, suite = ProtocolSuite.NETWORK, spec = "RFC792", description = "ip version 4")
public class Ip4 extends JHeaderMap<Ip4> implements JHeaderChecksum {

	/**
	 * The Class AddressExtension.
	 */
	@Header(id = 19)
	public static class AddressExtension extends IpOption {

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
	}

	/**
	 * The Class Encode.
	 */
	@Header(id = 15)
	public static class Encode extends IpOption {

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
	}

	/**
	 * The Class ExperimentalAccessControl.
	 */
	@Header(id = 14)
	public static class ExperimentalAccessControl extends IpOption {

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
	}

	/**
	 * The Class ExperimentalFlowControl.
	 */
	@Header(id = 13)
	public static class ExperimentalFlowControl extends IpOption {

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
	}

	/**
	 * The Class ExperimentalMeasurement.
	 */
	@Header(id = 10)
	public static class ExperimentalMeasurement extends IpOption {

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
	}

	/**
	 * The Class ExtendedIp.
	 */
	@Header(id = 17)
	public static class ExtendedIp extends IpOption {

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
	}

	/**
	 * Enum table for Ip4.flags field.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Flag {

		/** The DF. */
		DF,

		/** The MF. */
		MF
	}

	/**
	 * The Class IMITrafficDescriptor.
	 */
	@Header(id = 16)
	public static class IMITrafficDescriptor extends IpOption {

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
	}

	/**
	 * A table of IpTypes and their names.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Ip4Type implements JHeaderType {

		/** Authentication Header [RFC4302]. */
		AH("Authentication Header", 51),

		/** any host internal protocol [IANA]. */
		ANY_LOC("any host internal protocol", 61),

		/** ARGUS [RWS4]. */
		ARGUS("ARGUS", 13),

		/** BBN RCC Monitoring [SGC]. */
		BBN_RCC_MON("BBN RCC Monitoring", 10),

		/** BNA [Salamon]. */
		BNA("BNA", 49),

		/** CBT [Ballardie]. */
		CBT("CBT", 7),

		/** Chaos [NC3]. */
		CHAOS("Chaos", 16),

		/** Datagram Congestion Control Protocol [RFC4340]. */
		DCCP("Datagram Congestion Control Protocol", 33),

		/** DCN Measurement Subsystems [DLM1]. */
		DCN_MEAS("DCN Measurement Subsystems", 19),

		/** Datagram Delivery Protocol [WXC]. */
		DDP("Datagram Delivery Protocol", 37),

		/** Dynamic Source Routing Protocol [RFC4728]. */
		DSR("Dynamic Source Routing Protocol", 48),

		/** Exterior Gateway Protocol [RFC888][DLM1]. */
		EGP("Exterior Gateway Protocol", 8),

		/** EMCON [BN7]. */
		EMCON("EMCON", 14),

		/** Encap Security Payload [RFC4303]. */
		ESP("Encap Security Payload", 50),

		/** Fibre Channel [Rajagopal]. */
		FC("Fibre Channel", 133),

		/** Gateway-to-Gateway [RFC823]. */
		GGP("Gateway-to-Gateway", 3),

		/** General Routing Encapsulation [Li]. */
		GRE("General Routing Encapsulation", 47),

		/** Host Monitoring [RFC869][RH6]. */
		HMP("Host Monitoring", 20),

		/** IPv6 Hop-by-Hop Option [RFC1883]. */
		HOPORT("IPv6 Hop-by-Hop Option", 0),

		/** Integrated Net Layer Security TUBA [GLENN]. */
		I_NLSP("Integrated Net Layer Security  TUBA", 52),

		/** Internet Control Message [RFC792]. */
		ICMP("Internet Control Message", 1),

		/** Inter-Domain Policy Routing Protocol [MXS1]. */
		IDPR("Inter-Domain Policy Routing Protocol", 35),

		/** IDPR Control Message Transport Proto [MXS1]. */
		IDPR_CMTP("IDPR Control Message Transport Proto", 38),

		/** Inter-Domain Routing Protocol [Hares]. */
		IDRP("Inter-Domain Routing Protocol", 45),

		/** Internet Group Management [RFC1112]. */
		IGMP("Internet Group Management", 2),

		/** any private interior gateway [IANA] (used by Cisco for their IGRP). */
		IGP("any private interior gateway", 9),

		/** IL Transport Protocol [Presotto]. */
		IL("IL Transport Protocol", 40),

		/** Unreliable datagram protocol. */
		IP("IP in IP (encapsulation)", 4),

		/** IP-within-IP Encapsulation Protocol [JI6]. */
		IPIP("IP-within-IP Encapsulation Protocol", 94),

		/** Ipv6 [Deering]. */
		IPv6("Ipv6", 41),

		/** Fragment Header for IPv6 [Deering]. */
		IPv6_FRAG("Fragment Header for IPv6", 44),

		/** ICMP for IPv6 [RFC1883]. */
		IPv6_ICMP("ICMP for IPv6", 58),

		/** No Next Header for IPv6 [RFC1883]. */
		IPv6_NoNxt("No Next Header for IPv6", 59),

		/** Destination Options for IPv6 [RFC1883]. */
		IPv6_Opts("Destination Options for IPv6", 60),

		/** Routing Header for IPv6 [Deering]. */
		IPv6_ROUTE("Ipv6", 43),

		/** IPX in IP [Lee]. */
		IPX_In_IP("IPX in IP", 111),

		/** Internet Reliable Transaction [RFC938][TXM]. */
		IRTP("Internet Reliable Transaction", 28),

		/** ISO Transport Protocol Class 4 [RFC905][RC77]. */
		ISO_TP4("ISO Transport Protocol Class 4", 29),

		/** Leaf-1 [BWB6]. */
		LEAF_1("Leaf-1", 25),

		/** Leaf-2 [BWB6]. */
		LEAF_2("Leaf-2", 26),

		/** MERIT Internodal Protocol [HWB]. */
		MERIT_INP("MERIT Internodal Protocol", 32),

		/** MFE Network Services Protocol [MFENET][BCH2]. */
		MFE_NSP("MFE Network Services Protocol", 31),

		/** IP Mobility [Perkins]. */
		MOBILE("IP Mobility", 55),

		/** MPLS-in-IP [RFC4023]. */
		MPLS_in_IP("MPLS-in-IP", 137),

		/** Multiplexing [IEN90][JBP]. */
		MUX("Multiplexing", 18),

		/** NBMA Address Resolution Protocol [RFC1735]. */
		NARP("NBMA Address Resolution Protocol", 54),

		/** Bulk Data Transfer Protocol [RFC969][DDC1]. */
		NETBLT("Bulk Data Transfer Protocol", 30),

		/** PUP [PUP][XEROX]. */
		NVP_II("Network Voice Protocol", 11),

		/** Protocol Independent Multicast [Farinacci]. */
		PIM("Protocol Independent Multicast", 103),

		/** Packet Radio Measurement [ZSU]. */
		PRM("Packet Radio Measurement", 21),

		/** CBT [Ballardie]. */
		PUP("PUP", 12),

		/** Reliable Data Protocol [RFC908][RH6]. */
		RDP("Reliable Data Protocol", 27),

		/** Reservation Protocol [Braden]. */
		RSVP("Reservation Protocol", 46),

		/** Source Demand Routing Protocol [DXE1]. */
		SDRP("Source Demand Routing Protocol", 42),

		/** SKIP [Markson]. */
		SKIP("SKIP", 57),

		/** Stream Control Transport Protocol [RFC4960]. */
		SCTP("SCTP", 132),
		
		/** Stream [RFC1190][RFC1819]. */
		ST("Stream", 5),

		/** Schedule Transfer Protocol [JMP]. */
		STP("Schedule Transfer Protocol", 118),

		/** IP with Encryption [JI6]. */
		SWIPE("IP with Encryption", 53),

		/** Transmission Control [RFC793]. */
		TCP("Transmission Control", 6),

		/** Third Party Connect Protocol [SAF3]. */
		THIRD_PC("Third Party Connect Protocol", 34),

		/**
		 * Transport Layer Security Protocol [Oberg] using Kryptonet key management.
		 */
		TLSP("Transport Layer Security Protocol", 56),

		/** TP++ Transport Protocol [DXF]. */
		TP_PLUS("TP++ Transport Protocol", 39),

		/** Trunk-1 [BWB6]. */
		TRUNK_1("Trunk-1", 23),

		/** Trunk-2 [BWB6]. */
		TRUNK_2("Trunk-2", 24),

		/** User Datagram [RFC768][JBP]. */
		UDP("User Datagram", 17),

		/** Cross Net Debugger [IEN158][JFH2]. */
		XNET("Cross Net Debugger", 15),

		/** XEROX NS IDP [ETHERNET][XEROX]. */
		XNS_IDP("XEROX NS IDP", 22),

		/** XTP [GXC]. */
		XTP("XTP", 36), ;

		/**
		 * Name of the constant.
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
		 * Converts a numerical type to constant.
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
		 * Description of the type value.
		 * 
		 * @return description string
		 */
		public final String getDescription() {
			return this.description;
		}

		/**
		 * Converts contant to numerical ip type.
		 * 
		 * @return Ip4 type number
		 */
		public final int[] getTypeValues() {
			return this.typeValues;
		}
	}

	/**
	 * Baseclass for all Ip option headers.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class IpOption extends JSubHeader<Ip4> {

		/**
		 * The Enum CodeClass.
		 */
		public enum CodeClass {

			/** The CONTROL. */
			CONTROL(0),

			/** The DEBUG. */
			DEBUG(2),

			/** The RESERVE d1. */
			RESERVED1(1),

			/** The RESERVE d2. */
			RESERVED2(3), ;

			/**
			 * Value of.
			 * 
			 * @param cl
			 *          the cl
			 * @return the code class
			 */
			public static CodeClass valueOf(int cl) {
				for (CodeClass c : values()) {
					if (cl == c.cl) {
						return c;
					}
				}

				return null;
			}

			/** The cl. */
			private final int cl;

			/**
			 * Instantiates a new code class.
			 * 
			 * @param cl
			 *          the cl
			 */
			private CodeClass(int cl) {
				this.cl = cl;

			}
		}

		/**
		 * A table of IpOption types and their names.
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum OptionCode {
			/** The ADDRES s_ extension. */
			ADDRESS_EXTENSION(19),
			/** The DYNAMI c_ packe t_ state. */
			DYNAMIC_PACKET_STATE(23),
			/** The ENCODE. */
			ENCODE(15),
			/* 0 */
			/** The EN d_ o f_ optio n_ list. */
			END_OF_OPTION_LIST(0),
			/** The EXPERIMENTA l_ acces s_ control. */
			EXPERIMENTAL_ACCESS_CONTROL(14),
			/** The EXPERIMENTA l_ flo w_ control. */
			EXPERIMENTAL_FLOW_CONTROL(13),
			/** The EXPERIMENTA l_ measurement. */
			EXPERIMENTAL_MEASUREMENT(10),
			/** The EXTENDE d_ ip. */
			EXTENDED_IP(17),
			/** The IM i_ traffi c_ descriptor. */
			IMI_TRAFFIC_DESCRIPTOR(16),
			/* 3 */
			/** The LOOS e_ sourc e_ route. */
			LOOSE_SOURCE_ROUTE(3),

			/** The MT u_ probe. */
			MTU_PROBE(11),

			/** The MT u_ reply. */
			MTU_REPLY(12),

			/* 1 */
			/** The N o_ op. */
			NO_OP(1),

			/** The QUIC k_ start. */
			QUICK_START(25),

			/* 7 */
			/** The RECOR d_ route. */
			RECORD_ROUTE(7),

			/** The ROUTE r_ alert. */
			ROUTER_ALERT(20),

			/* 2 */
			/** The SECURITY. */
			SECURITY(2),

			/** The SELECTIV e_ directe d_ broadcas t_ most. */
			SELECTIVE_DIRECTED_BROADCAST_MOST(21),

			/* 8 */
			/** The STREA m_ id. */
			STREAM_ID(8),

			/* 9 */
			/** The STRIC t_ sourc e_ route. */
			STRICT_SOURCE_ROUTE(9),

			/* 4 */
			/** The TIMESTAMP. */
			TIMESTAMP(4),

			/** The TRACEROUTE. */
			TRACEROUTE(18),

			/* 5 */
			/** The UNASSIGNE d1. */
			UNASSIGNED1(5),

			/* 6 */
			/** The UNASSIGNE d2. */
			UNASSIGNED2(6),

			/** The UPSTREA m_ multicas t_ packet. */
			UPSTREAM_MULTICAST_PACKET(24), ;

			/**
			 * Value of.
			 * 
			 * @param id
			 *          the id
			 * @return the option code
			 */
			public static OptionCode valueOf(int id) {
				for (OptionCode c : values()) {
					if (c.id == id) {
						return c;
					}
				}

				return null;
			}

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
		 * Gets the Ip4.code field. Specifies the optional header type. <h3>Header
		 * Spec</h3>
		 * <table border=1>
		 * <tr>
		 * <td>Protocol Header:</td>
		 * <td>Ip4</td>
		 * </tr>
		 * <tr>
		 * <td>Protocol Family:</td>
		 * <td>Networking</td>
		 * </tr>
		 * <tr>
		 * <td>OSI Layer:</td>
		 * <td>3</td>
		 * </tr>
		 * <tr>
		 * <td>Field Property:</td>
		 * <td>constant offset</td>
		 * </tr>
		 * <tr>
		 * <td>Field Offset:</td>
		 * <td>getUByte(0) & 0x1F</td>
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
		@Field(offset = 0, length = 8, format = "%d")
		public int code() {
			return getUByte(0);
		}

		/**
		 * Sets the Ip4.code field. Specifies the optional header type. <h3>Header
		 * Spec</h3>
		 * <table border=1>
		 * <tr>
		 * <td>Protocol Header:</td>
		 * <td>Ip4</td>
		 * </tr>
		 * <tr>
		 * <td>Protocol Family:</td>
		 * <td>Networking</td>
		 * </tr>
		 * <tr>
		 * <td>OSI Layer:</td>
		 * <td>3</td>
		 * </tr>
		 * <tr>
		 * <td>Field Property:</td>
		 * <td>constant offset</td>
		 * </tr>
		 * <tr>
		 * <td>Field Offset:</td>
		 * <td>getUByte(0) & 0x1F</td>
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
		 * Code_ class.
		 * 
		 * @return the int
		 */
		@Field(parent = "code", offset = 5, length = 2, display = "class", format = "%d")
		public int code_Class() {
			return (code() & 0x60) >> 5;
		}

		/**
		 * Code_ class description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String code_ClassDescription() {
			return code_ClassEnum().toString();
		}

		/**
		 * Code_ class enum.
		 * 
		 * @return the code class
		 */
		public CodeClass code_ClassEnum() {
			return CodeClass.valueOf(code_Class());
		}

		/**
		 * Code_ copy.
		 * 
		 * @return the int
		 */
		@Field(parent = "code", offset = 7, length = 1, display = "copy", format = "%d")
		public int code_Copy() {
			return (code() & 0x80) >> 7;
		}

		/**
		 * Code_ copy description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String code_CopyDescription() {
			return (code_Copy() > 0) ? "copy to all fragments"
					: "do not copy to fragments";
		}

		/**
		 * Code_ type.
		 * 
		 * @return the int
		 */
		@Field(parent = "code", offset = 0, length = 5, display = "type", format = "%d")
		public int code_Type() {
			return (code() & 0x1F);
		}

		/**
		 * Code_ type description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String code_TypeDescription() {
			return IpOption.OptionCode.valueOf(code() & 0x1F).toString();
		}

		/**
		 * Gets the Ip4.code field. Specifies the optional header type. <h3>Header
		 * Spec</h3>
		 * <table border=1>
		 * <tr>
		 * <td>Protocol Header:</td>
		 * <td>Ip4</td>
		 * </tr>
		 * <tr>
		 * <td>Protocol Family:</td>
		 * <td>Networking</td>
		 * </tr>
		 * <tr>
		 * <td>OSI Layer:</td>
		 * <td>3</td>
		 * </tr>
		 * <tr>
		 * <td>Field Property:</td>
		 * <td>constant offset</td>
		 * </tr>
		 * <tr>
		 * <td>Field Offset:</td>
		 * <td>getUByte(0) & 0x1F</td>
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
		 * Sets the Ip4.code field. Specifies the optional header type. <h3>Header
		 * Spec</h3>
		 * <table border=1>
		 * <tr>
		 * <td>Protocol Header:</td>
		 * <td>Ip4</td>
		 * </tr>
		 * <tr>
		 * <td>Protocol Family:</td>
		 * <td>Networking</td>
		 * </tr>
		 * <tr>
		 * <td>OSI Layer:</td>
		 * <td>3</td>
		 * </tr>
		 * <tr>
		 * <td>Field Property:</td>
		 * <td>constant offset</td>
		 * </tr>
		 * <tr>
		 * <td>Field Offset:</td>
		 * <td>getUByte(0) & 0x1F</td>
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
	};

	/**
	 * Ip4 optional Loose Source Route header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 3)
	public static class LooseSourceRoute extends Routing {
	}

	/**
	 * The Class MtuProbe.
	 */
	@Header(id = 11)
	public static class MtuProbe extends IpOption {

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
	}

	/**
	 * The Class MtuReply.
	 */
	@Header(id = 12)
	public static class MtuReply extends IpOption {

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
	}

	/**
	 * Ip4 optional No Operation header. Takes up exactly 1 byte of memory.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 1)
	public static class NoOp extends IpOption {
	}

	/**
	 * Ip4 optional Record Route header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 7)
	public static class RecordRoute extends Routing {
	}

	/**
	 * The Class RouterAlert.
	 */
	@Header(id = 20)
	public static class RouterAlert extends IpOption {

		/**
		 * The Enum Action.
		 */
		public enum Action {

			/** The EXAMIN e_ packet. */
			EXAMINE_PACKET(0), ;

			/**
			 * Value of.
			 * 
			 * @param action
			 *          the action
			 * @return the action
			 */
			public static Action valueOf(int action) {
				for (Action a : values()) {
					if (a.value == action) {
						return a;
					}
				}

				return null;
			}

			/** The value. */
			private final int value;

			/**
			 * Instantiates a new action.
			 * 
			 * @param value
			 *          the value
			 */
			private Action(int value) {
				this.value = value;

			}

			/**
			 * Value.
			 * 
			 * @return the int
			 */
			public int value() {
				return value;
			}
		}

		/**
		 * Action.
		 * 
		 * @return the int
		 */
		@Field(offset = 16, length = 16)
		public int action() {
			return super.getUShort(2);
		}

		/**
		 * Action description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String actionDescription() {
			return actionEnum().toString();
		}

		/**
		 * Action enum.
		 * 
		 * @return the action
		 */
		public Action actionEnum() {
			return Action.valueOf(action());
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
	}

	/**
	 * Ip4 optional Routing header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class Routing extends IpOption {

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
		@Field(offset = 24, length = 0, format = "#ip4[]#")
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
	@Header(id = 2)
	public static class Security extends IpOption {

		/**
		 * A table of security algorithm types.
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
			return (getUShort(8) << 8) | getUByte(10); // 24 bits in
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
	 * The Class SelectiveDirectedBroadcastMode.
	 */
	@Header(id = 21)
	public static class SelectiveDirectedBroadcastMode extends IpOption {

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
	}

	/**
	 * Ip4 optional Stream ID header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 8)
	public static class StreamId extends IpOption {

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
	 * Ip4 optional Strict Source Route header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 9)
	public static class StrictSourceRoute extends Routing {
	}

	/**
	 * Ip4 optional Timestamp header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 4)
	public static class Timestamp extends IpOption {

		/**
		 * Ip4 optional Timestamp header - a timestamp entry.
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
		 * A table of Ip4 Timestamp header flags.
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
		 * Entries.
		 * 
		 * @return the entry[]
		 */
		@Field(offset = 4 * 8, format = "%s")
		public Entry[] entries() {
			final int flags = flags();

			if ((flags & FLAG_TIMESTAMP_WITH_IP) == 0) {
				return entriesTimestampOnly();

			} else {
				return entriesWithIp();
			}
		}

		/**
		 * Entries length.
		 * 
		 * @return the int
		 */
		@Dynamic(Field.Property.LENGTH)
		public int entriesLength() {
			return (length() - 4) * 8;
		}

		/**
		 * Entries timestamp only.
		 * 
		 * @return the entry[]
		 */
		private Entry[] entriesTimestampOnly() {
			final int length = length() - 4;
			final Entry[] entries = new Entry[length / 4];

			for (int i = 4, index = 0; i < length; i += 8, index++) {
				final Entry entry = entries[index] = new Entry();
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

			for (int i = 4, index = 0; i < length; i += 4, index++) {
				final Entry entry = entries[index] = new Entry();
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

	/**
	 * The Class Traceroute.
	 */
	@Header(id = 18)
	public static class Traceroute extends IpOption {

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

	// @Bind(to = Ethernet.class)
	// public static boolean bindToEthernet(JPacket packet, Ethernet eth) {
	// return eth.type() == 0x800;
	// }
	//
	// @Bind(to = IEEESnap.class)
	// public static boolean bindToSnap(JPacket packet, IEEESnap snap) {
	// return snap.pid() == 0x800;
	// }

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
	 * Calculates a checksum using protocol specification for a header. Checksums
	 * for partial headers or fragmented packets (unless the protocol alows it)
	 * are not calculated.
	 * 
	 * @return header's calculated checksum
	 */
	public int calculateChecksum() {
		return Checksum.inChecksumShouldBe(this.checksum(),
				Checksum.inChecksum(this, 0, this.size()));
	}

	/**
	 * Retrieves the header's checksum.
	 * 
	 * @return header's stored checksum
	 */
	@Field(offset = 10 * BYTE, length = 16, format = "%x")
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
	public boolean checksum(int value) {
		setUShort(10, value);

		return true;
	}

	/**
	 * Checksum description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {
		final int crc16 = calculateChecksum();
		if (checksum() == crc16) {
			return "correct";
		} else {
			return "incorrect: 0x" + Integer.toHexString(crc16).toUpperCase();
		}
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
	/**
	 * Decode header.
	 * 
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {
		optionsBitmap = 0;
		this.hashcode = (id() << 16) ^ sourceToInt() ^ destinationToInt() ^ type();

		// System.out.printf("offset=%d, %s %s", getOffset(), getPacket().getState()
		// .toDebugString(), toHexdump());
		final int hlen = hlen() * 4;

		for (int i = 20; i < hlen; i++) {
			final int id = getUByte(i) & 0x1F;
			optionsOffsets[id] = i;
			optionsBitmap |= (1 << id);

			final IpOption.OptionCode code = IpOption.OptionCode.valueOf(id);
			if (code == null) {
				break; // We are done, something seriously wrong with the header
			}

			switch (code) {
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

			// System.out.printf("i=%d id=%d bitmap=0x%X length=%d\n", i, id,
			// optionsBitmap, optionsLength[id]);
		}
	}

	/**
	 * Destination.
	 * 
	 * @return the byte[]
	 */
	@Field(offset = 16 * BYTE, length = 32, format = "#ip4#")
	@FlowKey(index = 0)
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
		setByteArray(16, value);
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
	 * Converts the 32 bit Ip4 destination address to a java signed 32 bit
	 * integer. The value returned should be treated as an unsigned integer, which
	 * java can not represent as an int. If neccessary to printout the value
	 * returned, in order to correctly represent the unsinged value, the integer
	 * returned should be converted to a java long type and sign appropriately
	 * handled to take advantage of the extra length of a java long type.
	 * 
	 * @return unsinged 32 bit integer representing the Ip4 destination address
	 */
	public int destinationToInt() {
		return getInt(16);
	}

	/**
	 * Retrives the flags header field as an unsigned integer, length of 3 bits,
	 * that has each Ip4 flag encoded as a bit field. The first flag is encoded in
	 * bit number 0 of the returned usigned integer.
	 * 
	 * @return 3 bits of the flag field as unsigned integer
	 */
	@Field(offset = 6 * BYTE, length = 3, format = "%x")
	public int flags() {
		return getUByte(6) >> 5;
	}

	/**
	 * A setter method that changes the flag bits directly in the peered Ip4
	 * header structure within the packet data buffer.
	 * 
	 * @param flags
	 *          new flags to set
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
	@Field(parent = "flags", offset = 1, length = 1, display = "DF: do not fragment")
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
	@Field(parent = "flags", offset = 0, length = 1, display = "MF: more fragments", nicname = "M")
	public int flags_MF() {
		return (flags() & FLAG_MORE_FRAGMENTS);
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

	/**
	 * Flags_ reserved.
	 * 
	 * @return the int
	 */
	@Field(parent = "flags", offset = 2, length = 1, display = "reserved")
	public int flags_Reserved() {
		return (flags() & FLAG_RESERVED) >> 3;
	}

	/**
	 * Retrieves the flags field as a collection's set of enum constants that
	 * represent each flag. The flags returned are an EnumSet which efficiently
	 * encodes the enum constants as an internal bitfield.
	 * 
	 * @return the sets the
	 */
	public Set<Ip4.Flag> flagsEnum() {
		Set<Ip4.Flag> set = EnumSet.noneOf(Ip4.Flag.class);
		if (flags_DF() > 0) {
			set.add(Ip4.Flag.DF);
		}

		if (flags_MF() > 0) {
			set.add(Ip4.Flag.MF);
		}

		return set;
	}

	/**
	 * Hash code.
	 * 
	 * @return the int
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
	@Field(offset = 0 * BYTE + 4, length = 4, format = "%d")
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
	@Field(offset = 4 * BYTE, length = 16, format = "%x")
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
	 * Checks if the checksum is valid, even for fragmented packets.
	 * 
	 * @return true if checksum checks out, otherwise if the computed checksum
	 *         does not match the stored checksum false is returned
	 */
	public boolean isChecksumValid() {

		return Checksum.inChecksum(this, 0, this.size()) == 0;
	}

	/**
	 * Checks if this is ip fragment of a larger PDU. The method checks offset and
	 * flags.MF fields to see if there are other fragments, marked by flags and
	 * offset, for a larger PDU.
	 * 
	 * @return true if this is a fragment, otherwise false
	 */
	public boolean isFragment() {
		return offset() != 0 || flags_MF() > 0;
	}

	/**
	 * Length.
	 * 
	 * @return the int
	 */
	@Field(offset = 2 * BYTE, length = 16, format = "%d")
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
	@Field(offset = 6 * BYTE + 3, length = 13, format = "%d")
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
	 * Offset description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String offsetDescription() {
		return (offset() == 0) ? null : "" + offset() + " * 8 = " + (offset() * 8)
				+ " bytes";
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
	 * Converts the 32 bit Ip4 source address to a java signed 32 bit integer. The
	 * value returned should be treated as an unsigned integer, which java can not
	 * represent as an int. If neccessary to printout the value returned, in order
	 * to correctly represent the unsinged value, the integer returned should be
	 * converted to a java long type and sign appropriately handled to take
	 * advantage of the extra length of a java long type.
	 * 
	 * @return unsinged 32 bit integer representing the Ip4 source address
	 */
	@Field(offset = 12 * BYTE, length = 32, format = "#ip4#")
	@FlowKey(index = 0)
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
	@Field(offset = 1 * BYTE, length = 8, format = "%x", display = "diffserv")
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
	@Field(offset = 8 * BYTE, length = 8, format = "%d", description = "time to live")
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
	@Field(offset = 9 * BYTE, length = 8, format = "%d")
	@FlowKey(index = 1)
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
		String next = Ip4Type.toString(type());
		return (offset() == 0) ? "next: " + next : "ip fragment"
				+ (next == null ? "" : " of " + next + " PDU");
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
