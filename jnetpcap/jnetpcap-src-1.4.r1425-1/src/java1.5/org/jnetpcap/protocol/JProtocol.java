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
package org.jnetpcap.protocol;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;
import org.jnetpcap.protocol.lan.IEEESnap;
import org.jnetpcap.protocol.lan.NullHeader;
import org.jnetpcap.protocol.lan.SLL;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.sigtran.Sctp;
import org.jnetpcap.protocol.sigtran.SctpAbort;
import org.jnetpcap.protocol.sigtran.SctpCWR;
import org.jnetpcap.protocol.sigtran.SctpCookie;
import org.jnetpcap.protocol.sigtran.SctpCookieAck;
import org.jnetpcap.protocol.sigtran.SctpData;
import org.jnetpcap.protocol.sigtran.SctpECNE;
import org.jnetpcap.protocol.sigtran.SctpError;
import org.jnetpcap.protocol.sigtran.SctpHeartbeat;
import org.jnetpcap.protocol.sigtran.SctpHeartbeatAck;
import org.jnetpcap.protocol.sigtran.SctpInit;
import org.jnetpcap.protocol.sigtran.SctpInitAck;
import org.jnetpcap.protocol.sigtran.SctpSack;
import org.jnetpcap.protocol.sigtran.SctpShutdown;
import org.jnetpcap.protocol.sigtran.SctpShutdownAck;
import org.jnetpcap.protocol.sigtran.SctpShutdownComplete;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.RtcpApp;
import org.jnetpcap.protocol.voip.RtcpBye;
import org.jnetpcap.protocol.voip.RtcpReceiverReport;
import org.jnetpcap.protocol.voip.RtcpSDES;
import org.jnetpcap.protocol.voip.RtcpSenderReport;
import org.jnetpcap.protocol.voip.Rtp;
import org.jnetpcap.protocol.voip.Sdp;
import org.jnetpcap.protocol.voip.Sip;
import org.jnetpcap.protocol.vpn.L2TP;
import org.jnetpcap.protocol.wan.PPP;

/**
 * Enum table of core protocols supported by jNetPcap. Various constants are
 * provided by this class and utility methods for working with protocol IDs,
 * Bitmasks and Maps.
 * 
 * <h2>Protocol IDs, Bitmasks and Maps</h2>
 * <p>
 * In the beginning with few network protocols defined and needed to be quickly
 * identified, a single 64-bit usigned integer was big enough to encode presence
 * of a protocol via bit encoding. However once that pool of usable bits began
 * to be exhausted it was necessary to implement fast lookup using a better
 * algorithm.
 * </p>
 * <p>
 * Since version 1.4, JProtocol class expanded the concept of protocol IDs.
 * Protocol ids are used to efficiently store information about the protocol
 * they identify. The ID of a protocol is used as a lookup in various tables
 * maintained by {@link JRegistry} and native state structures. This provides
 * extremely performance.
 * </p>
 * <p>
 * One may think of an ID as a global array index, that is assumed to be within
 * a certain range by all structures and objects in jNetPcap that can quickly
 * lookup information based on that particular "ID".
 * </p>
 * <p>
 * However IDs are not suitable for bitmask type operations. The native
 * structures in jNetPcap keep a running tally of which protocols are present in
 * a packet by setting certain bits, with a 1 to 1 correspondence to a given
 * protocol. The bitmasks are encoded in a special way to allow more then 64
 * protocols while still maintaining uniqueness for all protocols. As a matter
 * of fact, the current encoding scheme can encode and represent up to 128
 * billion protocols without conflict. Here is a diagram of a 64-bit bitmask
 * with its 2x32-bit fields.
 * 
 * <pre>
 * [32-bit map-index][32-bit bitmask (1 bit per protocol)]
 * </pre>
 * 
 * Where map-index represents a group of protocols, and each bit in a bitmask
 * corresponds to a protocol. The above encoding allows every single protocol to
 * be recorded in a fast lookup bitmask without the possibility of a conflicts
 * as long as each protocol is assigned a unique ID. IDs are easily convertible
 * to bitmasks and visa versa.
 * </p>
 * <p>
 * In essence, numerical IDs are divided into 32-bit id groups. Then a bit can
 * set for each protocol dissected within its own group. Most core protocols are
 * defined within the first group (group 0), but not all.
 * </p>
 * <h4>Combining protocol bitmasks</h4> One main benefit for bitmasks is that
 * one can do a check with the native packet structure to see if multiple
 * protocols are present within the packet. This results in a single native call
 * to retrieve the appropriate cumulative 64-bit bitmask from the packet state
 * structure and do a simple bitwise AND operation to make sure that all the
 * bits are matched meaning that all of the require protocols are there, or a
 * single or a subset of protocols is present.
 * <p>
 * There is however a restriction. The state structure keeps an array of
 * bitmasks and each protocol is mapped to a particular map-index. You can
 * combine any protocol map or ID into a single multi-bit bitmask as long as
 * each protocol being combined belongs to the same group. If there are 2
 * protocols in 2 different groups, then they can not be combined bitwise, and
 * one has to make to checks to see if each protocol is present. To make sure
 * that only compatible masks and ids are combined, 2 methods are provided
 * {@link #createMaskFromIds(int...)} and {@link #createMaskFromMasks(long...)}.
 * </p>
 * Example:
 * 
 * <pre>
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum JProtocol {

	/**
	 * Builtin header type that encapsulates the portion of the packet buffer
	 * not matched by any protocol header.
	 */
	PAYLOAD(JProtocol.PAYLOAD_ID, Payload.class),

	/** DIX Ethernet2 header. */
	ETHERNET(JProtocol.ETHERNET_ID, Ethernet.class, PcapDLT.EN10MB),

	/** Ip version 4 header. */
	IP4(JProtocol.IP4_ID, Ip4.class),

	/** Ip version 6 header. */
	IP6(JProtocol.IP6_ID, Ip6.class),

	/** TCP/IP header. */
	TCP(JProtocol.TCP_ID, Tcp.class),

	/** UDP/IP header. */
	UDP(JProtocol.UDP_ID, Udp.class),

	/**
	 * IEEE 802.3 header type
	 */
	IEEE_802DOT3(JProtocol.IEEE_802DOT3_ID, IEEE802dot3.class, PcapDLT.IEEE802),

	/** IEEE LLC2 header. */
	IEEE_802DOT2(JProtocol.IEEE_802DOT2_ID, IEEE802dot2.class),

	/** IEEE SNAP header. */
	IEEE_SNAP(JProtocol.IEEE_SNAP_ID, IEEESnap.class),

	/** IEEE VLAN tag header. */
	IEEE_802DOT1Q(JProtocol.IEEE_802DOT1Q_ID, IEEE802dot1q.class),

	/** Layer 2 tunneling protocol header. */
	L2TP(JProtocol.L2TP_ID, L2TP.class),

	/** Point to Point Protocol header. */
	PPP(JProtocol.PPP_ID, PPP.class, PcapDLT.PPP),

	/** Internet Control Message Protocol header. */
	ICMP(JProtocol.ICMP_ID, Icmp.class),

	/** Hyper Text Transmission Protocol header. */
	HTTP(JProtocol.HTTP_ID, Http.class),

	/** Hyper Text Markup Language header. */
	HTML(JProtocol.HTML_ID, Html.class),

	/** An Image header transmitted via http. */
	WEB_IMAGE(JProtocol.WEB_IMAGE_ID, WebImage.class),

	/** Address Resolution Protocol. */
	ARP(JProtocol.ARP_ID, Arp.class),

	/** Session Intiation Protocol. */
	SIP(JProtocol.SIP_ID, Sip.class),

	/** Session Data Protocol. */
	SDP(JProtocol.SDP_ID, Sdp.class),

	/** Realtime Transfer Protocol. */
	RTP(JProtocol.RTP_ID, Rtp.class),

	/** Linux cooked sockets. */
	SLL(JProtocol.SLL_ID, SLL.class, PcapDLT.LINUX_SLL),

	/** Stream Control Transport Protocol */
	SCTP(JProtocol.SCTP_ID, Sctp.class),

	/** SCTP Data Chunk */
	SCTP_DATA(JProtocol.SCTP_DATA_ID, SctpData.class),

	/** SCTP Init Chunk */
	SCTP_INIT(JProtocol.SCTP_INIT_ID, SctpInit.class),

	/** SCTP Init Acknowledgment Chunk */
	SCTP_INIT_ACK(JProtocol.SCTP_INIT_ACK_ID, SctpInitAck.class),

	/** SCTP Selective Acknowledgement Chunk */
	SCTP_SACK(JProtocol.SCTP_SACK_ID, SctpSack.class),

	/** SCTP Heartbeat Request Chunk */
	SCTP_HEARTBEAT(JProtocol.SCTP_HEARTBEAT_ID, SctpHeartbeat.class),

	/** SCTP Heartbeat Acknowledgment Chunk */
	SCTP_HEARTBEAT_ACK(JProtocol.SCTP_HEARTBEAT_ACK_ID, SctpHeartbeatAck.class),

	/** SCTP Abort Chunk */
	SCTP_ABORT(JProtocol.SCTP_ABORT_ID, SctpAbort.class),

	/** SCTP Shutdown Chunk */
	SCTP_SHUTDOWN(JProtocol.SCTP_SHUTDOWN_ID, SctpShutdown.class),

	/** SCTP Shutdown Acknowledgment Chunk */
	SCTP_SHUTDOWN_ACK(JProtocol.SCTP_SHUTDOWN_ACK_ID, SctpShutdownAck.class),

	/** SCTP Error Chunk */
	SCTP_ERROR(JProtocol.SCTP_ERROR_ID, SctpError.class),

	/** SCTP Cookie Echo/State Cookie Chunk */
	SCTP_COOKIE(JProtocol.SCTP_COOKIE_ID, SctpCookie.class),

	/** SCTP Cookie Acknowledgment Chunk */
	SCTP_COOKIE_ACK(JProtocol.SCTP_COOKIE_ACK_ID, SctpCookieAck.class),

	/** SCTP Explicit Congestion Notification Echo Chunk */
	SCTP_ECNE(JProtocol.SCTP_ECNE_ID, SctpECNE.class),

	/** SCTP Congestion Window Reduced Chunk */
	SCTP_CWR(JProtocol.SCTP_CWR_ID, SctpCWR.class),

	/** SCTP Shutdown Complete Chunk */
	SCTP_SHUTDOWN_COMPLETE(JProtocol.SCTP_SHUTDOWN_COMPLETE_ID,
			SctpShutdownComplete.class),

	/** NullHeader - loopback/null header */
	NULL_HEADER(JProtocol.NULL_HEADER_ID, NullHeader.class, PcapDLT.NULL),

	/** SR: Sender Report RTCP Packet */
	RTCP_SENDER_REPORT(JProtocol.RTCP_SENDER_REPORT_ID, RtcpSenderReport.class),

	/** RR: Receiver Report RTCP Packet */
	RTCP_RECEIVER_REPORT(JProtocol.RTCP_RECEIVER_REPORT_ID,
			RtcpReceiverReport.class),

	/** SDES: Source Description RTCP Packet */
	RTCP_SDES(JProtocol.RTCP_SDES_ID, RtcpSDES.class),

	/** BYE: Goodbye RTCP Packet */
	RTCP_BYE(JProtocol.RTCP_BYE_ID, RtcpBye.class),

	/** APP: Application-Defined RTCP Packet */
	RTCP_APP(JProtocol.RTCP_APP_ID, RtcpApp.class), ;

	/**
	 * A protocol suite. Meta data interface that provides general category for
	 * the protocol as a family of related protocols.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public interface Suite {

		/**
		 * Retrieves the name of the protocol suite.
		 * 
		 * @return name of the protocol family
		 */
		public String name();
	}

	/** Unique ID of this protocol. */
	private final int id;

	/** Main class for the network header of this protocol. */
	private Class<? extends JHeader> clazz;

	/** The class name. */
	private final String className;

	/**
	 * A header scanner that capable of scanning this protocol. All protocols
	 * defined in JProtocol are bound to a direct native scanner. While it is
	 * possible to override this default using JRegistery with a custom scanner.
	 */

	/**
	 * A mapping to pcap dlt. If no mapping exists for a protocol, it is null.
	 */
	private final PcapDLT[] dlt;

	/**
	 * Encoded bitmask for this protocol.
	 */
	private final long bitmask;

	/**
	 * Encoded group index
	 */
	private final int group;

	/**
	 * Bitmask to mask off the "protocol bits" portion.
	 */
	public final static long BITMASK_PROTCOL_MASK = 0x00000000FFFFFFFFL;

	/**
	 * Bitmask to mask off the "group bits" portion.
	 */
	public final static long BITMASK_GROUP_MASK = 0xFFFFFFFF00000000L;

	/**
	 * MAP GROUP 0
	 */
	public final static int BITMAP_GROUP0 = (0 << 5);

	/** The Constant PAYLOAD_ID. */
	public final static int PAYLOAD_ID = (BITMAP_GROUP0 | 0);

	/** The Constant ETHERNET_ID. */
	public final static int ETHERNET_ID = (BITMAP_GROUP0 | 1);

	/** The Constant IP4_ID. */
	public final static int IP4_ID = (BITMAP_GROUP0 | 2);

	/** The Constant IP6_ID. */
	public final static int IP6_ID = (BITMAP_GROUP0 | 3);

	/** The Constant TCP_ID. */
	public final static int TCP_ID = (BITMAP_GROUP0 | 4);

	/** The Constant UDP_ID. */
	public final static int UDP_ID = (BITMAP_GROUP0 | 5);

	/** The Constant IEEE_802DOT3_ID. */
	public final static int IEEE_802DOT3_ID = (BITMAP_GROUP0 | 6);

	/** The Constant IEEE_802DOT2_ID. */
	public final static int IEEE_802DOT2_ID = (BITMAP_GROUP0 | 7);

	/** The Constant IEEE_SNAP_ID. */
	public final static int IEEE_SNAP_ID = (BITMAP_GROUP0 | 8);

	/** The Constant IEEE_802DOT1Q_ID. */
	public final static int IEEE_802DOT1Q_ID = (BITMAP_GROUP0 | 9);

	/** The Constant L2TP_ID. */
	public final static int L2TP_ID = (BITMAP_GROUP0 | 10);

	/** The Constant PPP_ID. */
	public final static int PPP_ID = (BITMAP_GROUP0 | 11);

	/** The Constant ICMP_ID. */
	public final static int ICMP_ID = (BITMAP_GROUP0 | 12);

	/** The Constant HTTP_ID. */
	public final static int HTTP_ID = (BITMAP_GROUP0 | 13);

	/** The Constant HTML_ID. */
	public final static int HTML_ID = (BITMAP_GROUP0 | 14);

	/** The Constant WEB_IMAGE_ID. */
	public final static int WEB_IMAGE_ID = (BITMAP_GROUP0 | 15);

	/** The Constant ARP_ID. */
	public final static int ARP_ID = (BITMAP_GROUP0 | 16);

	/** The Constant SIP_ID. */
	public final static int SIP_ID = (BITMAP_GROUP0 | 17);

	/** The Constant SDP_ID. */
	public final static int SDP_ID = (BITMAP_GROUP0 | 18);

	/** The Constant SLL_ID. */
	public final static int SLL_ID = (BITMAP_GROUP0 | 20);

	/** NullHeader - loopback/null header */
	public final static int NULL_HEADER_ID = (BITMAP_GROUP0 | 21);

	/**
	 * BITMAP GROUP 1
	 */
	public final static int BITMAP_GROUP1 = (1 << 5);

	/** The Constant SCTP_ID. */
	public final static int SCTP_ID = (BITMAP_GROUP1 | 0);

	/** The Constant SCTP_DATA_ID. */
	public final static int SCTP_DATA_ID = (BITMAP_GROUP1 | 1);

	/** The Constant SCTP_INIT_ID. */
	public final static int SCTP_INIT_ID = (BITMAP_GROUP1 | 2);

	/** The Constant SCTP_INIT_ACK_ID. */
	public final static int SCTP_INIT_ACK_ID = (BITMAP_GROUP1 | 3);

	/** The Constant SCTP_SACK_ID. */
	public final static int SCTP_SACK_ID = (BITMAP_GROUP1 | 4);

	/** The Constant SCTP_HEARTBEAT_ID. */
	public final static int SCTP_HEARTBEAT_ID = (BITMAP_GROUP1 | 5);

	/** The Constant SCTP_HEARTBEAT_ID. */
	public final static int SCTP_HEARTBEAT_ACK_ID = (BITMAP_GROUP1 | 6);

	/** The Constant SCTP_ABORT_ID. */
	public final static int SCTP_ABORT_ID = (BITMAP_GROUP1 | 7);

	/** The Constant SCTP_SHUTDOWN_ID. */
	public final static int SCTP_SHUTDOWN_ID = (BITMAP_GROUP1 | 8);

	/** The Constant SCTP_SHUTDOWN_ACK_ID. */
	public final static int SCTP_SHUTDOWN_ACK_ID = (BITMAP_GROUP1 | 9);

	/** The Constant SCTP_ERROR_ID. */
	public final static int SCTP_ERROR_ID = (BITMAP_GROUP1 | 10);

	/** The Constant SCTP_COOKIE_ID. */
	public final static int SCTP_COOKIE_ID = (BITMAP_GROUP1 | 11);

	/** The Constant SCTP_COOKIE_ACK_ID. */
	public final static int SCTP_COOKIE_ACK_ID = (BITMAP_GROUP1 | 12);

	/** The Constant SCTP_ECNE_ID. */
	public final static int SCTP_ECNE_ID = (BITMAP_GROUP1 | 13);

	/** The Constant SCTP_CWR_ID. */
	public final static int SCTP_CWR_ID = (BITMAP_GROUP1 | 14);

	/** The Constant SCTP_SHUTDOWN_COMPLETE_ID. */
	public final static int SCTP_SHUTDOWN_COMPLETE_ID = (BITMAP_GROUP1 | 15);

	/** The Constant RTP_ID. */
	public final static int RTP_ID = (BITMAP_GROUP1 | 16);

	/** SR: Sender Report RTCP Packet */
	public final static int RTCP_SENDER_REPORT_ID = (BITMAP_GROUP1 | 17);

	/** RR: Receiver Report RTCP Packet */
	public final static int RTCP_RECEIVER_REPORT_ID = (BITMAP_GROUP1 | 18);

	/** SDES: Source Description RTCP Packet */
	public final static int RTCP_SDES_ID = (BITMAP_GROUP1 | 19);

	/** BYE: Goodbye RTCP Packet */
	public final static int RTCP_BYE_ID = (BITMAP_GROUP1 | 20);

	/** APP: Application-Defined RTCP Packet */
	public final static int RTCP_APP_ID = (BITMAP_GROUP1 | 21);

	/**
	 * BITMAP GROUP 2
	 */
	public final static int BITMAP_GROUP2 = (2 << 5);

	/** The Constant LAST_ID. */
	public final static int LAST_ID = BITMAP_GROUP2;

	/**
	 * Protocol descriptor constant
	 * 
	 * @param className
	 *            main protocol header class
	 */
	private JProtocol(int id, String className) {
		this(id, className, new PcapDLT[0]);
	}

	/**
	 * Protocol descriptor constant
	 * 
	 * @param c
	 *            protocol header class
	 */
	private JProtocol(int id, Class<? extends JHeader> c) {
		this(id, c, new PcapDLT[0]);
	}

	/**
	 * Protocol descriptor constant
	 * 
	 * @param c
	 *            protocol header class
	 * @param dlt
	 *            A corresponding Pcap data-link-type or first header for this
	 *            protocol
	 */
	private JProtocol(int id, Class<? extends JHeader> c, PcapDLT... dlt) {
		this.clazz = c;
		this.className = c.getCanonicalName();
		this.dlt = dlt;
		this.id = id;
		this.bitmask = idToMask(id);
		this.group = idToGroup(id);
	}

	/**
	 * Protocol descriptor constant
	 * 
	 * @param className
	 *            protocol header class
	 * @param dlt
	 *            A corresponding Pcap data-link-type or first header for this
	 *            protocol
	 */
	private JProtocol(int id, String className, PcapDLT... dlt) {
		this.className = className;
		this.dlt = dlt;
		this.id = id;
		this.bitmask = idToMask(id);
		this.group = idToGroup(id);

		if (getClass().getResource(className) == null) {
			throw new IllegalStateException("unable to find class " + className);
		}
	}

	/**
	 * Gets the header class.
	 * 
	 * @return the header class
	 */
	@SuppressWarnings("unchecked")
	public Class<? extends JHeader> getHeaderClass() {
		if (this.clazz == null) {
			try {
				this.clazz = (Class<? extends JHeader>) Class
						.forName(className);
			} catch (ClassNotFoundException e) {
				throw new IllegalStateException(e);
			}
		}

		return this.clazz;
	}

	/**
	 * Gets the header class name.
	 * 
	 * @return the header class name
	 */
	public String getHeaderClassName() {
		return this.className;
	}

	/**
	 * Checks the supplied ID if its is one of jNetPcap's core protocol set.
	 * 
	 * @param id
	 *            numerical ID of the header as assigned by JRegistry
	 * @return true if header is part of the core protocol set otherwise false
	 */
	public static boolean isCoreProtocol(int id) {
		return id < LAST_ID;
	}

	/**
	 * Checks the supplied header by class if its is one of jNetPcap's core
	 * protocol set.
	 * 
	 * @param c
	 *            class name of the header to check
	 * @return true if header is part of the core protocol set otherwise false
	 */
	public static boolean isCoreProtocol(Class<? extends JHeader> c) {
		return (valueOf(c) == null) ? false : true;
	}

	/**
	 * Converts a protocol header to a JPRotocol constant.
	 * 
	 * @param c
	 *            header class to convert
	 * @return an enum constant or null if class is not part of the core
	 *         protocol set
	 */
	public static JProtocol valueOf(Class<? extends JHeader> c) {
		for (JProtocol p : values()) {
			if (p.clazz == c) {
				return p;
			}
		}

		return null;
	}

	/**
	 * Converts a protocol header to a JPRotocol constant.
	 * 
	 * @param id
	 *            numerical ID of the header assigned by JRegistry
	 * @return an enum constant or null if class is not part of the core
	 *         protocol set
	 */
	public static JProtocol valueOf(int id) {
		if (id >= values().length) {
			return null;
		}

		return values()[id];
	}

	/**
	 * Gets the numerical ID of the data link header for the open pcap handle. A
	 * call to Pcap.datalink() is made and the value translated to an
	 * appropriate jNetPcap protocol header ID.
	 * 
	 * @param pcap
	 *            open Pcap handle
	 * @return enum constant or the Payload header as the catch all if no
	 *         headers are matched
	 */
	public static JProtocol valueOf(Pcap pcap) {
		return valueOf(PcapDLT.valueOf(pcap.datalink()));
	}

	/**
	 * Gets the numerical ID of the data link header for supplied pcap dlt
	 * constant. A call to Pcap.datalink() is made and the value translated to
	 * an appropriate jNetPcap protocol header ID.
	 * 
	 * @param dlt
	 *            pcap dlt constant
	 * @return enum constant or the Payload header as the catch all if no
	 *         headers are matched
	 */
	public static JProtocol valueOf(PcapDLT dlt) {
		if (dlt == null) {
			return PAYLOAD;
		}

		for (JProtocol p : values()) {

			for (PcapDLT d : p.dlt) {
				if (dlt == d) {
					return p;
				}
			}
		}

		return PAYLOAD; // Not found
	}

	/**
	 * Gets the corresponding Pcap defined Data Link Type.
	 * 
	 * @return the dlt dlt for this protocol
	 */
	public PcapDLT[] getDlt() {
		return dlt;
	}

	/**
	 * Gets a unique runtime numerica ID of this protocol assigned by
	 * jNetStream.
	 * 
	 * @return the protocol id
	 */
	public int getId() {
		return id;
	}

	public long getBitmask() {
		return this.bitmask;
	}

	public int getGroup() {
		return this.group;
	}

	/**
	 * Gets the main class for the network header of this protocol.
	 * 
	 * @return the main class for the network header of this protocol
	 */
	public final Class<? extends JHeader> getClazz() {
		return this.clazz;
	}

	/**
	 * Encodes a linear protocol index (a JRegistry index), into a bitmask based
	 * ID.
	 * 
	 * @param index
	 *            zero based linear JRegistry protocol index (table index).
	 *            Allowed values are from 0 to 1024.
	 * @return encoded 64-bit unique protocol identifier
	 * @since 1.4
	 */
	public static long idToMask(int index) {
		if (index < 0 || index >= JRegistry.MAX_ID_COUNT) {
			throw new IllegalArgumentException(
					"valid index values are between 0 and "
							+ JRegistry.MAX_ID_COUNT);
		}

		long mapIndex = index >> 5; // For high-order 32 bits (1-based)

		long mask = mapIndex << 32 | (1L << (index & 0x1F));

		return mask;
	}

	/**
	 * Given a packet header bitmask, creates a numerical ID that can be used
	 * for array lookups
	 * 
	 * @param map
	 *            map group to create the ID for
	 * @param index
	 *            zero based index within the group (0 to 31)
	 * @return numerical id
	 * @since 1.4
	 */
	public final static int createId(int map, int index) {
		return map << 5 | index;
	}

	/**
	 * Gets the map-group index from a bitmask
	 * 
	 * @param mask
	 *            mask to extra map-group index
	 * @return map-group index
	 * @since 1.4
	 */
	public final static int maskToGroup(long mask) {
		return (int) (mask >> 32); // bits 32 throw 37 are the map index in a
									// mask
	}

	/**
	 * Gets the map-group index to which the given ID should be mapped
	 * 
	 * @param id
	 *            id to use from map-group index calculation
	 * @return map-group index
	 * @since 1.4
	 */
	public final static int idToGroup(int id) {
		return id >> 5; // bits 6 through 11 are the map index in ID
	}

	/**
	 * Converts a mask to a numerical ID
	 * 
	 * @param mask
	 *            mask containing a single protocol bit encoded
	 * @return corresponding ID
	 * @since 1.4
	 */
	public static int maskToId(long mask) {
		int c = 32;

		/* Count number of 0 bits on the right */
		if (mask != 0)
			c--;
		if ((mask & 0x0000FFFF) != 0)
			c -= 16;
		if ((mask & 0x00FF00FF) != 0)
			c -= 8;
		if ((mask & 0x0F0F0F0F) != 0)
			c -= 4;
		if ((mask & 0x33333333) != 0)
			c -= 2;
		if ((mask & 0x55555555) != 0)
			c -= 1;

		return (int) ((mask >> 37) | c);
	}

	/**
	 * Safely combines multiple MASKS into a single mask suitable for OR with
	 * header-map-bitmasks. The bitmasks must all belong to the same map-group
	 * otherwise an exception is thrown.
	 * 
	 * @param masks
	 *            masks to combine
	 * @return combined masks
	 * @since 1.4
	 */
	public static long createMaskFromMasks(long... masks) {
		long c = 0;
		final int constraint = maskToGroup(masks[0]);

		for (long m : masks) {
			if (maskToGroup(m) != constraint) {
				throw new IllegalArgumentException(
						"All masks must be in the same map-index");
			}

			c |= m;
		}

		return c;
	}

	/**
	 * Safely combines multiple MASKS into a single mask suitable for OR with
	 * header-map-bitmasks. The bitmasks must all belong to the same map-group
	 * otherwise an exception is thrown.
	 * 
	 * @param protocols
	 *            protocols to combine
	 * @return combined masks
	 * @since 1.4
	 */
	public static long createMaskFromProtocols(JProtocol... protocols) {

		long c = 0;
		final int constraint = protocols[0].group;

		for (JProtocol p : protocols) {
			if (p.group != constraint) {
				throw new IllegalArgumentException(
						"All protocols must be in the same bitmap-group");
			}

			c |= p.bitmask;
		}

		return c;
	}

	/**
	 * Safely combines multiple MASKS into a single mask suitable for OR with
	 * header-map-bitmasks. The bitmasks must all belong to the same map-group
	 * otherwise an exception is thrown.
	 * 
	 * @param masks
	 *            masks to combine
	 * @return combined masks
	 * @since 1.4
	 */
	public static long createMaskFromIds(int... ids) {
		long c = 0;
		final int constraint = idToGroup(ids[0]);

		for (int i : ids) {
			long m = idToMask(i);
			if (maskToGroup(m) != constraint) {
				throw new IllegalArgumentException(
						"All ids must be in the same bitmap-group");
			}

			c |= m;
		}

		return c;
	}
}