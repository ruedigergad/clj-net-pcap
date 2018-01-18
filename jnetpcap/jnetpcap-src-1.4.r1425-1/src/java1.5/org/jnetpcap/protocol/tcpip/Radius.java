/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011 Sly Technologies, Inc.
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
package org.jnetpcap.protocol.tcpip;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldSetter;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.Header.Layer;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.format.JFormatter.Style;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.tcpip.radius.FreeRadiusDictionary;
import org.jnetpcap.protocol.tcpip.radius.FreeRadiusDictionary.Attribute;
import org.jnetpcap.protocol.tcpip.radius.FreeRadiusDictionary.Vendor;
import org.jnetpcap.protocol.tcpip.radius.RadiusAVPField;

/**
 * <p>
 * Remote Authentication Dial In User Service (RADIUS) is a networking protocol
 * that provides centralized Authentication, Authorization, and Accounting (AAA)
 * management for computers to connect and use a network service. RADIUS was
 * developed by Livingston Enterprises, Inc., in 1991 as an access server
 * authentication and accounting protocol and later brought into the Internet
 * Engineering Task Force (IETF) standards.
 * </p>
 * <p>
 * Because of the broad support and the ubiquitous nature of the RADIUS
 * protocol, it is often used by ISPs and enterprises to manage access to the
 * Internet or internal networks, wireless networks, and integrated e-mail
 * services. These networks may incorporate modems, DSL, access points, VPNs,
 * network ports, web servers, etc.
 * </p>
 * <p>
 * RADIUS is a client/server protocol that runs in the application layer, using
 * UDP as transport. The Remote Access Server, the Virtual Private Network
 * server, the Network switch with port-based authentication, and the Network
 * Access Server (NAS), are all gateways that control access to the network, and
 * all have a RADIUS client component that communicates with the RADIUS server.
 * The RADIUS server is usually a background process running on a UNIX or
 * Windows NT machine.[3] RADIUS serves three functions: *
 * </p>
 * <p>
 * <ul>
 * <li>to authenticate users or devices before granting them access to a
 * network,
 * <li>to authorize those users or devices for certain network services and
 * <li>to account for usage of those services.
 * </ul>
 * </p>
 * 
 * @author Sly Technologies, Inc.
 * 
 */
@Header(
		description = "Remote Authentication Dial-In User Service",
		osi = Layer.APPLICATION)
public class Radius extends JHeader {

	public enum AVType {
		INTEGER("integer"),
		IPADDR("ipaddr"),
		IPXADDR("ipxaddr"),
		IP6ADDR("ip6addr"),
		IP6PREFIX("ip6prefix"),
		STRING("string"),
		DATE("date"),
		IFID("ifid"),
		OCTETS("octets");

		private final String str;

		private AVType(String str) {
			this.str = str;

		}

		public static AVType parseAVType(String type) {
			for (AVType t : values()) {
				if (type.equals(t.str)) {
					return t;
				}
			}

			return OCTETS;
		}
	}

	public enum Code {
		ACCESS_ACCEPT(2), // Catch all
		ACCESS_CHALLENGE(11),
		ACCESS_REJECT(3),
		ACCESS_REQUEST(1),
		ACCOUNTING_MESSAGE(10),
		ACCOUNTING_REQUEST(4),
		ACCOUNTING_RESPONSE(5),
		ACCOUNTING_STATUS(6),
		ALTERNATE_RESOURCE_RECLAIM_REQUEST(25),
		COA_ACK(44),
		COA_NAK(45),
		COA_REQUEST(43),
		DISCONNECT_ACK(41),
		DISCONNECT_NACK(42),
		DISCONNECT_REQUEST(40),
		EVENT_REQUEST(33),
		EVENT_RESPONSE(34),
		IP_ADDRESS_ALLOCATE(50),
		IP_ADDRESS_RELEASE(51),
		NAS_REBOOT_REQUEST(26),
		NAS_REBOOT_RESPONSE(27),
		NEW_PIN(30),
		NEXT_PASSCODE(29),
		PASSWORD_ACK(8),
		PASSWORD_EXPIRED(32),
		PASSWORD_REJECT(9),
		PASSWORD_REQUEST(7),
		RESERVED(0),
		RESERVED14(14),
		RESERVED15(15),
		RESERVED16(16),
		RESERVED17(17),
		RESERVED18(18),
		RESERVED19(19),
		RESERVED20(20),
		RESERVED28(28),
		RESERVED35(35),
		RESERVED36(36),
		RESERVED37(37),
		RESERVED38(38),
		RESERVED39(39),
		RESERVED46(46),
		RESERVED47(47),
		RESERVED48(48),
		RESERVED49(49),
		RESOURCE_FREE_REQUEST(21),
		RESOURCE_FREE_RESPONSE(22),
		RESOURCE_QUERY_REQUEST(23),
		RESOURCE_QUERY_RESPONSE(24),
		STATUS_CLIENT(13),
		STATUS_SERVER(12),
		TERMINATE_SESSION(31), ;
		public static Code valueOf(int value) {
			for (Code c : values()) {
				if (c.value == value) {
					return c;
				}
			}

			return RESERVED;
		}

		public final int value;

		private Code(int value) {
			this.value = value;
		}
	}

	private static class Data {
		public long code;
		public int l = 1;
		public int length;
		public int offset;
		public int t = 1;
		public long vendor;
	}

	public enum Type {
		ACCT_AUTHENTIC(45, AVType.INTEGER),
		ACCT_DELAY_TIME(41, AVType.INTEGER),
		ACCT_INPUT_GIGAWORDS(52, AVType.OCTETS),
		ACCT_INPUT_OCTETS(42, AVType.INTEGER),
		ACCT_INPUT_PACKETS(47, AVType.INTEGER),
		ACCT_INTERIM_INTERVAL(85, AVType.OCTETS),
		ACCT_LINK_COUNT(51, AVType.OCTETS),
		ACCT_MULTI_SESSION_ID(50, AVType.OCTETS),
		ACCT_OUTPUT_OCTETS(43, AVType.INTEGER),
		ACCT_OUTPUT_PACKETS(48, AVType.INTEGER),
		ACCT_SESSION_ID(44, AVType.OCTETS),
		ACCT_SESSION_TIME(46, AVType.INTEGER),
		ACCT_STATUS_TYPE(40, AVType.INTEGER),
		ACCT_TERMINATE_CAUSE(49, AVType.INTEGER),
		ACCT_TUNNEL_CONNECTION(68, AVType.OCTETS),
		ACCT_TUNNEL_PACKETS_LOST(86, AVType.OCTETS),
		ARAP_CHALLENGE_RESPONE(84, AVType.OCTETS),
		ARAP_FEATURES(71, AVType.OCTETS),
		ARAP_PASSWORD(70, AVType.OCTETS),
		ARAP_SECURITY(73, AVType.OCTETS),
		ARAP_SECURITY_DATA(74, AVType.OCTETS),
		ARAP_ZONE_ACCESS(72, AVType.OCTETS),
		BASIC_LOCASTION_POLICY_RULES(129, AVType.OCTETS),
		CALLBACK_ID(20, AVType.OCTETS),
		CALLBACK_NUMBER(19, AVType.OCTETS),
		CALLED_STATION_ID(30, AVType.STRING),
		CALLING_STATION_ID(31, AVType.STRING),
		CHAP_CHALLENGE(60, AVType.OCTETS),
		CHAP_PASSWORD(3, AVType.STRING),
		CHARGEABLE_USER_IDENTITY(89, AVType.OCTETS),
		CLASS(25, AVType.OCTETS),
		CONFIGURATION_TOKEN(78, AVType.OCTETS),
		CONNECT_INFO(77, AVType.OCTETS),
		DELEGATE_IPV6_PREFIX(123, AVType.OCTETS),
		DIGEST_AKA_AUTS(118, AVType.OCTETS),
		DIGEST_ALGORITHM(111, AVType.OCTETS),
		DIGEST_AUTH_PARAM(117, AVType.OCTETS),
		DIGEST_CNONCE(113, AVType.OCTETS),
		DIGEST_DOMAIN(119, AVType.OCTETS),
		DIGEST_ENTITY_BODY_HASH(112, AVType.OCTETS),
		DIGEST_HA1(121, AVType.OCTETS),
		DIGEST_METHOD(108, AVType.OCTETS),
		DIGEST_NEXTNONCE(106, AVType.OCTETS),
		DIGEST_NONCE(105, AVType.OCTETS),
		DIGEST_NONCE_COUNT(114, AVType.OCTETS),
		DIGEST_OPAQUE(116, AVType.OCTETS),
		DIGEST_QOP(110, AVType.OCTETS),
		DIGEST_REALM(104, AVType.OCTETS),
		DIGEST_REPOSE_AUTH(107, AVType.OCTETS),
		DIGEST_RESPONSE(103, AVType.OCTETS),
		DIGEST_STALE(120, AVType.OCTETS),
		DIGEST_URI(109, AVType.OCTETS),
		DIGEST_USERNAME(115, AVType.OCTETS),
		EAP_KEY_NAME(102, AVType.OCTETS),
		EAP_MESSAGE(79, AVType.OCTETS),
		EGRESS_VLAN_NAME(58, AVType.OCTETS),
		EGRESS_VLANID(56, AVType.OCTETS),
		ERROR_CAUSE(101, AVType.OCTETS),
		EVENT_TIMESTAMP(55, AVType.DATE),
		EXTENDED_LOCATION_POLICY_RULES(130, AVType.OCTETS),
		FILTER_ID(11, AVType.OCTETS),
		FRAMED_APPLETALK_LINK(37, AVType.OCTETS),
		FRAMED_APPLETALK_NETWORK(38, AVType.OCTETS),
		FRAMED_APPLETALK_ZONE(39, AVType.OCTETS),
		FRAMED_COMPRESSION(13, AVType.INTEGER),
		FRAMED_INTERFACE_ID(96, AVType.OCTETS),
		FRAMED_IP_ADDRESS(8, AVType.IPADDR),
		FRAMED_IP_NETMASK(9, AVType.IPADDR),
		FRAMED_IPV6_POOL(100, AVType.OCTETS),
		FRAMED_IPV6_PREFIX(97, AVType.OCTETS),
		FRAMED_IPV6_ROUTE(99, AVType.OCTETS),
		FRAMED_IPX_NETWORK(23, AVType.IPXADDR),
		FRAMED_MANAGEMENT_PROTOCOL(133, AVType.OCTETS),
		FRAMED_MTU(12, AVType.INTEGER),
		FRAMED_POOL(88, AVType.OCTETS),
		FRAMED_PROTOCOL(7, AVType.INTEGER),
		FRAMED_ROUTE(22, AVType.OCTETS),
		FRAMED_ROUTING(10, AVType.IPADDR),
		IDLE_TIMEOUT(28, AVType.INTEGER),
		INGRESS_FILTERS(57, AVType.OCTETS),
		INVALID(0, AVType.OCTETS),
		LOCASTION_CAPABLE(131, AVType.OCTETS),
		LOCATION_DATA(128, AVType.OCTETS),
		LOCATION_INFORMATION(127, AVType.OCTETS),
		LOGIN_IP_HOST(14, AVType.IPADDR),
		LOGIN_IPV6_HOST(98, AVType.OCTETS),
		LOGIN_LAT_GROUP(36, AVType.OCTETS),
		LOGIN_LAT_NODE(35, AVType.OCTETS),
		LOGIN_LAT_PORT(63, AVType.OCTETS),
		LOGIN_LAT_SERVICE(34, AVType.OCTETS),
		LOGIN_SERVICE(15, AVType.INTEGER),
		LOGIN_TCP_PORT(16, AVType.INTEGER),
		MANAGEMENT_POLICY_ID(135, AVType.OCTETS),
		MANAGEMENT_PRIVILEGE_LEVEL(136, AVType.OCTETS),
		MANAGEMENT_TRANSPORT_PROTECTION(134, AVType.OCTETS),
		MESSAGE_AUTHENTICATOR(80, AVType.OCTETS),
		MIP6_FEATURE_VECTOR(124, AVType.OCTETS),
		MIPS_HOME_LINK_PREFIX(125, AVType.OCTETS),
		NAS_FILTER_RULE(92, AVType.OCTETS),
		NAS_IDENTIFIER(32, AVType.STRING),
		NAS_IP_ADDRESS(4, AVType.IPADDR),
		NAS_IPV6_ADDRESS(95, AVType.OCTETS),
		NAS_PORT(5, AVType.INTEGER),
		NAS_PORT_ID(87, AVType.OCTETS),
		NAS_PORT_TYPE(61, AVType.INTEGER),
		OPERATOR_NAME(126, AVType.OCTETS),
		ORIGINATING_LINE_INFO(94, AVType.OCTETS),
		PASSWORD_RETRY(75, AVType.OCTETS),
		PKM_AUTH_KEY(143, AVType.OCTETS),
		PKM_AUTH_WAIT_TIMEOUT(139, AVType.OCTETS),
		PKM_CA_CERT(138, AVType.OCTETS),
		PKM_CRYPTOSUITE_LIST(140, AVType.OCTETS),
		PKM_SA_DESCRIPTOR(142, AVType.OCTETS),
		PKM_SAID(141, AVType.OCTETS),
		PKM_SS_CERT(137, AVType.OCTETS),
		PORT_LIMIT(62, AVType.INTEGER),
		PROMPT(76, AVType.OCTETS),
		PROXY_STATE(33, AVType.OCTETS),
		REPLY_MESSAGE(18, AVType.OCTETS),
		REQUESTED_LOCATION_INFO(132, AVType.OCTETS),
		RESERVED17(17, AVType.OCTETS),
		RESERVED21(21, AVType.OCTETS),
		RESERVED54(54, AVType.OCTETS),
		RESERVED93(93, AVType.OCTETS),
		SERVICE_TYPE(6, AVType.INTEGER),
		SESSION_TIMEOUT(27, AVType.INTEGER),
		SIP_AOR(122, AVType.OCTETS),
		STATE(24, AVType.OCTETS),
		TERMINATION_ACTION(29, AVType.OCTETS),
		TUNNEL_ASSIGNMENT_ID(82, AVType.OCTETS),
		TUNNEL_CLIENT_AUTH_ID(90, AVType.OCTETS),
		TUNNEL_CLIENT_ENDPOINT(66, AVType.OCTETS),
		TUNNEL_MEDIUM_TYPE(65, AVType.OCTETS),
		TUNNEL_PASSWORD(69, AVType.OCTETS),
		TUNNEL_PREFERENCE(83, AVType.OCTETS),
		TUNNEL_PRIVATE_GROUP_ID(81, AVType.OCTETS),
		TUNNEL_SERVER_AUTH_ID(91, AVType.OCTETS),
		TUNNEL_SERVER_ENDPOINT(67, AVType.OCTETS),
		TUNNEL_TYPE(64, AVType.OCTETS),
		USER_NAME(1, AVType.STRING),
		USER_PASSWORD(2, AVType.STRING),
		USER_PRIORITY_TABLE(59, AVType.OCTETS),
		VENDOR_SPECIFIC(26, AVType.OCTETS),

		;
		public static Type valueOf(int value) {
			for (Type c : values()) {
				if (c.value == value) {
					return c;
				}
			}

			return INVALID;
		}

		public final AVType data;

		public final int value;

		private Type(int value) {
			this.value = value;
			this.data = AVType.OCTETS;
		}

		private Type(int value, AVType data) {
			this.value = value;
			this.data = data;
		}

	}

	private final static Type[] attributeTypes = new Type[256];

	private final static int CAPACITY = 256;

	private final static FreeRadiusDictionary dictionary;

	static {

		/*
		 * Initialize the attribute type table
		 */
		for (int i = 0; i < attributeTypes.length; i++) {
			attributeTypes[i] = Type.INVALID;
		}

		for (Type t : Type.values()) {
			attributeTypes[t.value] = t;
		}

		dictionary = new FreeRadiusDictionary();

		try {
			dictionary.process();
			JRegistry.register(Radius.class);
		} catch (RegistryHeaderErrors e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Bind(to = Udp.class)
	public static boolean bind2Udp(JPacket packet, Udp udp) {
		return udp.destination() == 1812 || udp.source() == 1812 // Server
				|| udp.destination() == 1813 || udp.source() == 1813 // Accounting
				|| udp.destination() == 3799 || udp.source() == 3799 // Authorization
				|| udp.destination() == 1646 || udp.source() == 1646; // Obsolete
	}

	@HeaderLength()
	public static int headerLength(JBuffer buffer, int offset) {
		return buffer.getUShort(16);
	}

	private final List<JField> avps = new ArrayList<JField>(64);

	private final Data[] data = new Data[CAPACITY];

	private int dataCount = 0;

	{
		for (int i = 0; i < CAPACITY; i++) {
			data[i] = new Data();
		}
	}

	public int attributeInt(int code) {
		return attributeInt(0, code);
	}

	public int attributeInt(int vendor, int code) {
		final Data d = findData(vendor, code);
		if (d == null) {
			return 0;
		}

		return super.getInt(d.offset + d.t + d.l);
	}

	public byte[] attributeIp6addr(int code) {
		return attributeIp6addr(0, code);
	}

	public byte[] attributeIp6addr(int vendor, int code) {
		final Data d = findData(vendor, code);
		if (d == null) {
			return null;
		}

		return super.getByteArray(d.offset + d.t + d.l, 16);
	}

	public byte[] attributeIpaddr(int code) {
		return attributeIpaddr(0, code);
	}

	public byte[] attributeIpaddr(int vendor, int code) {
		final Data d = findData(vendor, code);
		if (d == null) {
			return null;
		}

		return super.getByteArray(d.offset + d.t + d.l, 4);
	}

	public byte[] attributeOctets(int code) {
		return attributeOctets(0, code);
	}

	public byte[] attributeOctets(int vendor, int code) {
		final Data d = findData(vendor, code);
		if (d == null) {
			return null;
		}

		return super.getByteArray(d.offset + d.t + d.l, d.length - d.t - d.l);
	}

	public String attributeString(int code) {
		return attributeString(0, code);

	}

	public String attributeString(int vendor, int code) {
		final Data d = findData(vendor, code);
		if (d == null) {
			return null;
		}

		return super.getUTF8String(d.offset + d.t + d.l, d.length - d.t - d.l);

	}

	public long attributeTime(int code) {
		return attributeTime(0, code);
	}

	public long attributeTime(int vendor, int code) {
		final Data d = findData(vendor, code);
		if (d == null) {
			return 0;
		}

		return super.getUInt(d.offset + d.t + d.l);
	}

	public long attributeUInt(int code) {
		return attributeUInt(0, code);
	}

	public long attributeUInt(int vendor, int code) {
		final Data d = findData(vendor, code);
		if (d == null) {
			return 0;
		}

		return super.getUInt(d.offset + d.t + d.l);
	}

	@Field(offset = 4 * BYTE, length = 16 * BYTE, format = "#octets#")
	public byte[] authenticator() {
		return super.getByteArray(4, 16);
	}

	@FieldSetter
	public void authenticator(byte[] value) {
		if (value.length != 16) {
			throw new IllegalArgumentException("expecting 16 byte array");
		}
		super.setByteArray(8, value);
	}

	public byte[] authenticatorByteArray(byte[] storage) {
		return super.getByteArray(8, storage);
	}

	@Field(offset = 0 * BYTE, length = 1 * BYTE)
	public int code() {
		return super.getUByte(0);
	}

	@FieldSetter
	public void code(int value) {
		super.setUByte(0, value);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String codeDescription() {
		return codeEnum().toString();
	}

	public Code codeEnum() {
		return Code.valueOf(code());
	}

	private RadiusAVPField createAVP(int offset,
			Attribute at,
			long code,
			int length) {

		int start = offset + 2;
		int len = length - 2;

		if (at.typeString.equals("string")) {
			String name = String.format("%s", at.name);
			String value = getUTF8String(start, len);
			return new RadiusAVPField(name, (int) code, offset, len, value,
					Style.STRING);
		}

		if (at.typeString.equals("integer")) {
			String name = String.format("%s", at.name);
			long value = getUInt(start);
			String description = at.values.get(value);
			if (description == null) {
				return new RadiusAVPField(name, (int) code, offset, len, value,
						Style.INT_DEC);
			} else {
				return new RadiusAVPField(name, (int) code, offset, len, value,
						Style.INT_DEC, description);
			}
		}

		if (at.typeString.equals("ipaddr") || at.typeString.equals("ipv4prefix")) {
			String name = String.format("%s", at.name);
			byte[] value = getByteArray(start, 4);
			return new RadiusAVPField(name, (int) code, offset, len, value,
					Style.BYTE_ARRAY_IP4_ADDRESS);
		}

		if (at.typeString.equals("ipv6addr")) {
			String name = String.format("%s", at.name);
			byte[] value = getByteArray(start, 16);
			return new RadiusAVPField(name, (int) code, offset, len, value,
					Style.BYTE_ARRAY_IP6_ADDRESS);
		}

		if (at.typeString.equals("octets")) {
			String name = String.format("%s", at.name);
			byte[] value = getByteArray(start, len);
			return new RadiusAVPField(name, (int) code, offset, len, value,
					Style.BYTE_ARRAY_OCTET_STREAM);
		}

		return null;
	}

	private RadiusAVPField createAVP(final int offset,
			final int type,
			final int len,
			final AVType data) {

		final String name = Type.valueOf(type).name();

		Style style;
		Object value;
		switch (data) {
		case INTEGER:
			value = super.getInt(offset + 2);
			style = Style.INT_DEC;
			break;

		case IPADDR:
			value = getByteArray(offset + 2, 4);
			style = Style.BYTE_ARRAY_IP4_ADDRESS;
			break;

		case STRING:
			value = getUTF8String(offset + 2, len - 2);
			style = Style.STRING;
			break;

		case DATE:
			value = getUInt(offset + 2);
			style = Style.TIMESTAMP_SECONDS;
			break;

		case OCTETS:
			value = getByteArray(offset + 2, len - 2);
			style = Style.BYTE_ARRAY_OCTET_STREAM;
			break;

		default:
			throw new IllegalStateException("unknow AVP type: " + data);
		}

		return new RadiusAVPField(name, type, offset, len, value, style);

	}

	private RadiusAVPField createSVA(int offset,
			Vendor vendor,
			Attribute at,
			long code,
			int length) {

		int start = offset + vendor.typeLen + vendor.lenLen;
		int len = length - vendor.typeLen - vendor.lenLen;

		String name = String.format(" +%s", at.name);
		if (at.typeString.equals("string")) {
			String value = getUTF8String(start, len);
			return new RadiusAVPField(name, (int) code, offset, len, value,
					Style.STRING);
		}

		if (at.typeString.equals("integer")) {
			long value = getUInt(start);
			String description = at.values.get(value);
			if (description == null) {
				return new RadiusAVPField(name, (int) code, offset, len, value,
						Style.INT_DEC);
			} else {
				return new RadiusAVPField(name, (int) code, offset, len, value,
						Style.INT_DEC, description);
			}
		}

		if (at.typeString.equals("ipaddr") || at.typeString.equals("ipv4prefix")) {
			byte[] value = getByteArray(start, 4);
			return new RadiusAVPField(name, (int) code, offset, len, value,
					Style.BYTE_ARRAY_IP4_ADDRESS);
		}

		if (at.typeString.equals("ipv6addr")) {
			byte[] value = getByteArray(start, 16);
			return new RadiusAVPField(name, (int) code, offset, len, value,
					Style.BYTE_ARRAY_IP6_ADDRESS);
		}

		if (at.typeString.equals("octets")) {
			byte[] value = getByteArray(start, len);
			return new RadiusAVPField(name, (int) code, offset, len, value,
					Style.BYTE_ARRAY_OCTET_STREAM);
		}

		return null;
	}

	/**
	 * 
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {
		avps.clear();
		dataCount = 0;

		final int hl = length();
		Vendor vendor = null;

		int len = 0;
		for (int i = 20; i < hl; i += len) {
			final int type = super.getUByte(i);
			len = super.getUByte(i + 1);

			switch (type) {
			case 26: // VENDOR SPECIFIC ATTRIBUTE
				long code = getUInt(i + 2);

				if (vendor == null || vendor.code != code) {
					vendor = dictionary.vendor(code);
				}

				final int t = (vendor == null) ? 1 : vendor.typeLen;
				final int l = (vendor == null) ? 1 : vendor.lenLen;

				long vtype = 0;
				if (t == 1) {
					vtype = getUByte(i + 6);
				} else if (t == 2) {
					vtype = getUShort(i + 6);
				} else if (t == 4) {
					vtype = getInt(i + 6);
				}

				int vlen = t;
				if (l == 1) {
					vlen = getUByte(i + 6 + t);
				} else if (l == 2) {
					vlen = getUShort(i + 6 + t);
				} else if (l == 4) {
					vlen = getInt(i + 6 + t);
				}

				Data d = data[dataCount++];
				d.code = vtype;
				d.length = vlen;
				d.vendor = code;
				d.offset = i + 6;
				d.t = t;
				d.l = l;
				break;

			default:
				d = data[dataCount++];
				d.code = type;
				d.length = len;
				d.vendor = 0;
				d.offset = i;
				d.t = 1;
				d.l = 1;
				break;

			}
		}
	}

	protected void decodeHeaderToAVPFields() {

		JField[] header = super.getFields();
		for (JField f : header) {
			avps.add(f);
		}

		final int hl = length();

		int len = 0;
		for (int i = 20; i < hl; i += len) {
			final Type type = attributeTypes[super.getUByte(i)];
			len = super.getUByte(i + 1);

			switch (type) {
			case VENDOR_SPECIFIC:
				long code = getUInt(i + 2);

				Vendor vendor = dictionary.vendor(code);

				long vtype = 0;
				if (vendor.typeLen == 1) {
					vtype = getUByte(i + 6);
				} else if (vendor.typeLen == 2) {
					vtype = getUShort(i + 6);
				} else if (vendor.typeLen == 4) {
					vtype = getInt(i + 6);
				}

				int vlen = vendor.typeLen;
				if (vendor.lenLen == 1) {
					vlen = getUByte(i + 6 + vendor.typeLen);
				} else if (vendor.lenLen == 2) {
					vlen = getUShort(i + 6 + vendor.typeLen);
				} else if (vendor.lenLen == 4) {
					vlen = getInt(i + 6 + vendor.typeLen);
				}

				int o = i + 6 + vendor.typeLen + vendor.lenLen;

				int start = i + 6 + vendor.typeLen + vendor.lenLen;
				int vdlen = vlen - vendor.typeLen - vendor.lenLen;

				Attribute at = vendor.attributes.get(vtype);

				if (at == null) {
					String name = String.format("+unknown(%s:%d)", vendor.name, vtype);
					RadiusAVPField avp = new RadiusAVPField(name, o, vlen);
					avp.setAvpType((int) vtype);
					avp.setValue(getByteArray(start, vdlen));
					avp.setStyle(Style.BYTE_ARRAY_OCTET_STREAM);

					avps.add(avp);
				} else {
					RadiusAVPField avp = createSVA(i + 6, vendor, at, vtype, vlen);
					if (avp != null) {
						avps.add(avp);
					}
				}

				break;

			default:
				at = dictionary.attributes.get((long) type.value);
				if (at == null) {
					avps.add(createAVP(i, type.value, len, type.data));
					break;
				}

				RadiusAVPField avp = createAVP(i, at, type.value, len);
				if (avp != null) {
					avps.add(avp);
				}
			}
		}
	}

	private Data findData(int vendor, int code) {
		for (int i = 0; i < dataCount; i++) {
			final Data d = data[i];
			if (d.vendor == vendor && d.code == code) {
				return d;
			}
		}

		return null;
	}

	/**
	 * @return
	 * @see org.jnetpcap.packet.JHeader#getFields()
	 */
	@Override
	public JField[] getFields() {
		if (avps.isEmpty()) {
			decodeHeaderToAVPFields();
		}

		return avps.toArray(new JField[avps.size()]);
	}

	@Field(offset = 1 * BYTE, length = 1 * BYTE)
	public int identifier() {
		return super.getUByte(1);
	}

	@FieldSetter
	public void identifier(int value) {
		super.setUByte(1, value);
	}

	@Field(offset = 2 * BYTE, length = 2 * BYTE, units = "bytes")
	public int length() {
		return super.getUShort(2);
	}

	@FieldSetter
	public void length(int value) {
		super.setUShort(2, value);
	}

	@SuppressWarnings("unused")
	@Field(
			offset = 20 * BYTE,
			length = 1 * BYTE,
			display = "= = = = = = = = = = = = =",
			format = "%s")
	private String separatorLine() {
		return "= = = = = = = = = = = = =";
	}
}
