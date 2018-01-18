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
package org.jnetpcap.protocol.tcpip;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.checksum.Checksum;

// TODO: Auto-generated Javadoc
/**
 * User Datagram Protocol (UDP).
 * <p>
 * The User Datagram Protocol (UDP) is one of the core members of the Internet
 * Protocol Suite, the set of network protocols used for the Internet. With UDP,
 * computer applications can send messages, in this case referred to as
 * datagrams, to other hosts on an Internet Protocol (IP) network without
 * requiring prior communications to set up special transmission channels or
 * data paths. The protocol was designed by David P. Reed in 1980 and formally
 * defined in RFC 768.
 * </p>
 * <p>
 * UDP uses a simple transmission model without implicit hand-shaking dialogues
 * for providing reliability, ordering, or data integrity. Thus, UDP provides an
 * unreliable service and datagrams may arrive out of order, appear duplicated,
 * or go missing without notice. UDP assumes that error checking and correction
 * is either not necessary or performed in the application, avoiding the
 * overhead of such processing at the network interface level. Time-sensitive
 * applications often use UDP because dropping packets is preferable to waiting
 * for delayed packets, which may not be an option in a real-time system. If
 * error correction facilities are needed at the network interface level, an
 * application may use the Transmission Control Protocol (TCP) or Stream Control
 * Transmission Protocol (SCTP) which are designed for this purpose.
 * </p>
 * <p>
 * UDP's stateless nature is also useful for servers answering small queries
 * from huge numbers of clients. Unlike TCP, UDP is compatible with packet
 * broadcast (sending to all on local network) and multicasting (send to all
 * subscribers).
 * </p>
 * <p>
 * Common network applications that use UDP include: the Domain Name System
 * (DNS), streaming media applications such as IPTV, Voice over IP (VoIP),
 * Trivial File Transfer Protocol (TFTP) and many online games.
 * </p>
 * <p>
 * UDP is a minimal message-oriented Transport Layer protocol that is documented
 * in IETF RFC 768.
 * </p>
 * <p>
 * UDP provides no guarantees to the upper layer protocol for message delivery
 * and the UDP protocol layer retains no state of UDP messages once sent. For
 * this reason, UDP is sometimes referred to as Unreliable Datagram Protocol.
 * </p>
 * <p>
 * UDP provides application multiplexing (via port numbers) and integrity
 * verification (via checksum) of the header and payload. If transmission
 * reliability is desired, it must be implemented in the user's application.
 * </p>
 * <p>
 * The UDP header consists of 4 fields, all of which are 2 bytes (16 bits). The
 * use of two of those is optional in IPv4 (pink background in table). In IPv6
 * only the source port is optional:
 * <ul>
 * <li><b>Source port number</b> - This field identifies the sender's port when
 * meaningful and should be assumed to be the port to reply to if needed. If not
 * used, then it should be zero. If the source host is the client, the port
 * number is likely to be an ephemeral port number. If the source host is the
 * server, the port number is likely to be a well-known port number.
 * <li><b>Destination port number</b> - This field identifies the receiver's
 * port and is required. Similar to source port number, if the client is the
 * destination host then the port number will likely be an ephemeral port number
 * and if the destination host is the server then the port number will likely be
 * a well-known port number.
 * <li><b>Length</b> - A field that specifies the length in bytes of the entire
 * datagram: header and data. The minimum length is 8 bytes since that's the
 * length of the header. The field size sets a theoretical limit of 65,535 bytes
 * (8 byte header + 65,527 bytes of data) for a UDP datagram. The practical
 * limit for the data length which is imposed by the underlying IPv4 protocol is
 * 65,507 bytes (65,535 - 8 byte UDP header - 20 byte IP header).
 * <li><b>Checksum</b> - The checksum field is used for error-checking of the
 * header and data. If the checksum is omitted in IPv4, the field uses the value
 * all-zeros. This field is not optional for IPv6.
 * </ul>
 * </p>
 * Description source: http://wikipedia.org/wiki/User_Datagram_Protocol
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 8)
public class Udp extends JHeader implements JHeaderChecksum {

	/** Unique numerical ID of this header. */
	public static final int ID = JProtocol.UDP_ID;

	/**
	 * Calculates a checksum using protocol specification for a header. Checksums
	 * for partial headers or fragmented packets (unless the protocol alows it)
	 * are not calculated.
	 * <p>
	 * The method used to compute the checksum is defined in RFC 768:
	 * 
	 * <pre>
	 * Checksum is the 16-bit one's complement of the one's complement sum of 
	 * a pseudo header of information from the IP header, the UDP header, 
	 * and the data, padded with zero octets at the end (if necessary) to make 
	 * a multiple of two octets.
	 * </pre>
	 * 
	 * In other words, all 16-bit words are summed using one's complement
	 * arithmetic. The sum is then one's complemented to yield the value of the
	 * UDP checksum field. If the checksum calculation results in the value zero
	 * (all 16 bits 0) it should be sent as the one's complement (all 1's). The
	 * difference between IPv4 and IPv6 is in the data used to compute the
	 * checksum.
	 * </p>
	 * 
	 * @return header's calculated checksum
	 */
	public int calculateChecksum() {

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.inChecksumShouldBe(checksum(),
				Checksum.pseudoUdp(this.packet, ipOffset, getOffset()));
	}

	/**
	 * The checksum field is used for error-checking of the header and data. If
	 * the checksum is omitted in IPv4, the field uses the value all-zeros. This
	 * field is not optional for IPv6.
	 * 
	 * @return value of checksum field as 16-bit unsigned integer
	 */
	@Field(offset = 6 * 8, length = 16, format = "%x")
	public int checksum() {
		return getUShort(6);
	}

	/**
	 * Sets the new value for checksum field in the header. Typical usage is
	 * 
	 * <pre>
	 * Udp udp = ...; // Acquire a udp header from somewhere
	 * udp.destination(123);
	 * udp.source(321);
	 * udp.checksum(udp.cacluateChecksum());
	 * </pre>
	 * 
	 * @param value
	 *          new unsigned 16-bit integer value for checksum
	 */
	public boolean checksum(final int value) {
		super.setUShort(6, value);

		return true;
	}

	/**
	 * Returns a dynamic description of the checksum field. Specifically it checks
	 * and displays, as description, the state of the checksum field, if it
	 * matches the calculated checksum or not.
	 * 
	 * @return additional information about the state of the checksum field
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {

		if (isFragmented()) {
			return "supressed for fragments";
		}

		if (isPayloadTruncated()) {
			return "supressed for truncated packets";
		}

		final int checksum = checksum();
		if (checksum == 0) {
			return "omitted";
		}

		final int crc16 = calculateChecksum();
		if (checksum == crc16) {
			return "correct";
		} else {
			return "incorrect: 0x" + Integer.toHexString(crc16).toUpperCase();
		}
	}

	/**
	 * This field identifies the receiver's port and is required. Similar to
	 * source port number, if the client is the destination host then the port
	 * number will likely be an ephemeral port number and if the destination host
	 * is the server then the port number will likely be a well-known port number.
	 * 
	 * @return value of destination port as 16-bit unsigned integer
	 */
	@Field(offset = 2 * 8, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int destination() {
		return getUShort(2);
	}

	/**
	 * Sets a new unsigned 16-bit integer value for the udp port number field.
	 * 
	 * @param value
	 *          new value to be stored in the destination field
	 */
	public void destination(final int value) {
		setUShort(2, value);
	}

	/**
	 * Checks if the checksum is valid, for un-fragmented packets. If a packet is
	 * fragmented, the checksum is not verified as data to is incomplete, but the
	 * method returns true none the less.
	 * 
	 * @return true if checksum checks out or if this is a fragment, otherwise if
	 *         the computed checksum does not match the stored checksum false is
	 *         returned
	 */
	public boolean isChecksumValid() {

		if (isFragmented()) {
			return true;
		}

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.pseudoUdp(this.packet, ipOffset, getOffset()) == 0;
	}

	/**
	 * A field that specifies the length in bytes of the entire datagram: header
	 * and data. The minimum length is 8 bytes since that's the length of the
	 * header. The field size sets a theoretical limit of 65,535 bytes (8 byte
	 * header + 65,527 bytes of data) for a UDP datagram. The practical limit for
	 * the data length which is imposed by the underlying Ip4 protocol is 65,507
	 * bytes (65,535 - 8 byte UDP header - 20 byte IP header).
	 * 
	 * @return value of length field as 16-bit unsigned integer
	 */
	@Field(offset = 4 * 8, length = 16)
	public int length() {
		return getUShort(4);
	}

	/**
	 * Sets a new unsigned 16-bit integer value for the udp field.
	 * 
	 * @param value
	 *          new value to be stored in the length field
	 */
	public void length(final int value) {
		setUShort(4, value);
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
	 * This field identifies the sender's port when meaningful and should be
	 * assumed to be the port to reply to if needed. If not used, then it should
	 * be zero. If the source host is the client, the port number is likely to be
	 * an ephemeral port number. If the source host is the server, the port number
	 * is likely to be a well-known port number.
	 * 
	 * @return value of source port as 16-bit unsigned integer
	 */
	@Field(offset = 0, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int source() {
		return getUShort(0);
	}

	/**
	 * Sets a new unsigned 16-bit integer value for the udp port number field.
	 * 
	 * @param value
	 *          new value to be stored in the source field
	 */
	public void source(final int value) {
		setUShort(0, value);
	}

}
