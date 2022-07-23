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

import java.util.EnumSet;
import java.util.Set;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.BindingVariable;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.util.checksum.Checksum;

// TODO: Auto-generated Javadoc
/**
 * Transmission Control Protocol (TCP).
 * <p>
 * The Transmission Control Protocol (TCP) is one of the core protocols of the
 * Internet Protocol Suite. TCP is one of the two original components of the
 * suite, complementing the Internet Protocol (IP) and therefore the entire
 * suite is commonly referred to as TCP/IP. TCP provides the service of
 * exchanging data reliably directly between two network hosts, whereas IP
 * handles addressing and routing message across one or more networks. In
 * particular, TCP provides reliable, ordered delivery of a stream of bytes from
 * a program on one computer to another program on another computer. TCP is the
 * protocol that major Internet applications rely on, such as the World Wide
 * Web, e-mail, and file transfer. Other applications, which do not require
 * reliable data stream service, may use the User Datagram Protocol (UDP) which
 * provides a datagram service, which emphasizes reduced latency over
 * reliability.
 * </p>
 * <p>
 * A TCP segment consists of a segment header and a data section. The TCP header
 * contains 10 mandatory fields, and an optional extension field (Options).
 * </p>
 * <p>
 * The data section follows the header. Its contents are the payload data
 * carried for the application. The length of the data section is not specified
 * in the TCP segment header. It can be calculated by subtracting the combined
 * length of the TCP header and the encapsulating IP segment header from the
 * total IP segment length (specified in the IP segment header).
 * </p>
 * <p>
 * The header structure is as follows:
 * <ul>
 * <li>Source port (16 bits) - identifies the sending port
 * <li>Destination port (16 bits) - identifies the receiving port
 * <li>Sequence number (32 bits) - has a dual role:
 * <ul>
 * <li>If the SYN flag is set, then this is the initial sequence number. The
 * sequence number of the actual first data byte (and the acknowledged number in
 * the corresponding ACK) are then this sequence number plus 1.
 * <li>If the SYN flag is clear, then this is the accumulated sequence number of
 * the first data byte of this packet for the current session.
 * </ul>
 * <li>Acknowledgment number (32 bits) - if the ACK flag is set then the value
 * of this field is the next sequence number that the receiver is expecting.
 * This acknowledges receipt of all prior bytes (if any). The first ACK sent by
 * each end acknowledges the other end's initial sequence number itself, but no
 * data.
 * <li>Data offset (4 bits) - specifies the size of the TCP header in 32-bit
 * words. The minimum size header is 5 words and the maximum is 15 words thus
 * giving the minimum size of 20 bytes and maximum of 60 bytes, allowing for up
 * to 40 bytes of options in the header. This field gets its name from the fact
 * that it is also the offset from the start of the TCP segment to the actual
 * data.
 * <li>Reserved (4 bits) - for future use and should be set to zero
 * <li>Flags (8 bits) (aka Control bits) - contains 8 1-bit flags
 * <ul>
 * <li>CWR (1 bit) - Congestion Window Reduced (CWR) flag is set by the sending
 * host to indicate that it received a TCP segment with the ECE flag set and had
 * responded in congestion control mechanism (added to header by RFC 3168).
 * <li>ECE (1 bit) - ECN-Echo indicates If the SYN flag is set, that the TCP
 * peer is ECN capable. If the SYN flag is clear, that a packet with Congestion
 * Experienced flag in IP header set is received during normal transmission
 * (added to header by RFC 3168).
 * <li>URG (1 bit) - indicates that the Urgent pointer field is significant
 * <li>ACK (1 bit) - indicates that the Acknowledgment field is significant. All
 * packets after the initial SYN packet sent by the client should have this flag
 * set.
 * <li>PSH (1 bit) - Push function. Asks to push the buffered data to the
 * receiving application.
 * <li>RST (1 bit) - Reset the connection
 * <li>SYN (1 bit) - Synchronize sequence numbers. Only the first packet sent
 * from each end should have this flag set. Some other flags change meaning
 * based on this flag, and some are only valid for when it is set, and others
 * when it is clear.
 * <li>FIN (1 bit) - No more data from sender
 * </ul>
 * <li>Window (16 bits) - the size of the receive window, which specifies the
 * number of bytes (beyond the sequence number in the acknowledgment field) that
 * the receiver is currently willing to receive (see Flow control and Window
 * Scaling)
 * <li>Checksum (16 bits) - The 16-bit checksum field is used for error-checking
 * of the header and data
 * <li>Urgent pointer (16 bits) - if the URG flag is set, then this 16-bit field
 * is an offset from the sequence number indicating the last urgent data byte
 * <li>Options (Variable 0-320 bits, divisible by 32) - The length of this field
 * is determined by the data offset field. Options 0 and 1 are a single byte (8
 * bits) in length. The remaining options indicate the total length of the
 * option (expressed in bytes) in the second byte. Some options may only be sent
 * when SYN is set; they are indicated below as [SYN].
 * <ul>
 * <li>0 (8 bits) - End of options list
 * <li>1 (8 bits) - No operation (NOP, Padding) This may be used to align option
 * fields on 32-bit boundaries for better performance.
 * <li>2,4,SS (32 bits) - Maximum segment size (see maximum segment size) [SYN]
 * <li>3,3,S (24 bits) - Window scale (see window scaling for details) [SYN]
 * <li>4,2 (16 bits) - Selective Acknowledgement permitted. [SYN] (See selective
 * acknowledgments for details)
 * <li>5,N,BBBB,EEEE,... (variable bits, N is either 10, 18, 26, or 34)-
 * Selective ACKnowlegement (SACK) These first two bytes are followed by a list
 * of 1-4 blocks being selectively acknowledged, specified as 32-bit begin/end
 * pointers.
 * <li>8,10,TTTT,EEEE (80 bits)- Timestamp and echo of previous timestamp (see
 * TCP Timestamps for details)
 * <li>14,3,S (24 bits) - TCP Alternate Checksum Request. [SYN]
 * <li>15,N,... (variable bits) - TCP Alternate Checksum Data.
 * </ul>
 * </ul>
 * (The remaining options are obsolete, experimental, not yet standardized, or
 * unassigned)
 * </p>
 * Description source: http://wikipedia.org/wiki/Tcp_protocol
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
@SuppressWarnings("unused")
public class Tcp extends JHeaderMap<Tcp> implements JHeaderChecksum {

	/**
	 * The option described in this memo provides a mechanism to negotiate the
	 * use of an alternate checksum at connection-establishment time, as well as
	 * a mechanism to carry additional checksum information for algorithms that
	 * utilize checksums that are longer than 16 bits.
	 * <p>
	 * Definition of the option: the TCP Alternate Checksum Request Option may
	 * be sent in a SYN segment by a TCP to indicate that the TCP is prepared to
	 * both generate and receive checksums based on an alternate algorithm.
	 * During communication, the alternate checksum replaces the regular TCP
	 * checksum in the checksum field of the TCP header. Should the alternate
	 * checksum require more than 2 bytes to transmit, the checksum may either
	 * be moved into a TCP Alternate Checksum Data Option and the checksum field
	 * of the TCP header be sent as 0, or the data may be split between the
	 * header field and the option. Alternate checksums are computed over the
	 * same data as the regular TCP checksum.
	 * </p>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 15)
	public static class AlternateChecksum extends TcpOption {

		/**
		 * This field is used only when the alternate checksum that is
		 * negotiated is longer than 16 bits. These checksums will not fit in
		 * the checksum field of the TCP header and thus at least part of them
		 * must be put in an option. Whether the checksum is split between the
		 * checksum field in the TCP header and the option or the entire
		 * checksum is placed in the option is determined on a checksum by
		 * checksum basis.
		 * 
		 * @return variable length alternate checksum data
		 */
		@Field(offset = 2 * BYTE, format = "#hexdump#")
		public byte[] data() {
			return getByteArray(2, dataLength() / 8); // Allocates a new array
		}

		/**
		 * Determines the length of this dynamic field.
		 * 
		 * @return length of the data field in bits
		 */
		@Dynamic(Field.Property.LENGTH)
		public int dataLength() {
			return (length() - 2) * BYTE; // In bits
		}

		/**
		 * This field is used only when the alternate checksum that is
		 * negotiated is longer than 16 bits. These checksums will not fit in
		 * the checksum field of the TCP header and thus at least part of them
		 * must be put in an option. Whether the checksum is split between the
		 * checksum field in the TCP header and the option or the entire
		 * checksum is placed in the option is determined on a checksum by
		 * checksum basis.
		 * 
		 * @param array
		 *            copies data into the supplied array
		 * @return the supplied array
		 */
		public byte[] dataToArray(byte[] array) {
			return getByteArray(2, array);
		}
	}

	/**
	 * The option described in this memo provides a mechanism to negotiate the
	 * use of an alternate checksum at connection-establishment time, as well as
	 * a mechanism to carry additional checksum information for algorithms that
	 * utilize checksums that are longer than 16 bits.
	 * <p>
	 * Definition of the option: the TCP Alternate Checksum Request Option may
	 * be sent in a SYN segment by a TCP to indicate that the TCP is prepared to
	 * both generate and receive checksums based on an alternate algorithm.
	 * During communication, the alternate checksum replaces the regular TCP
	 * checksum in the checksum field of the TCP header. Should the alternate
	 * checksum require more than 2 bytes to transmit, the checksum may either
	 * be moved into a TCP Alternate Checksum Data Option and the checksum field
	 * of the TCP header be sent as 0, or the data may be split between the
	 * header field and the option. Alternate checksums are computed over the
	 * same data as the regular TCP checksum.
	 * </p>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 14)
	public static class AlternateChecksumRequest extends TcpOption {

		/**
		 * A SYN segment used to originate a connection may contain the
		 * Alternate Checksum Request Option, which specifies an alternate
		 * checksum-calculation algorithm to be used for the connection. The
		 * acknowledging SYN-ACK segment may also carry the option.
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum Algorithm {
			/**
			 * Redundant Checksum Avoidance.
			 */
			AVOIDANCE(3),

			/**
			 * 16-bit Fletcher's algorithm.
			 */
			FLETCHER_16BIT(2),
			/**
			 * 8-bit Fletcher's algorithm.
			 */
			FLETCHER_8BIT(1),

			/**
			 * TCP checksum.
			 */
			TCP_CHECKSUM(0);

			/**
			 * Converts a numerical algorithm type to enum constant.
			 * 
			 * @param type
			 *            numerical type
			 * @return enum constant type
			 */
			public static Algorithm valueOf(int type) {
				for (Algorithm a : values()) {
					if (type == a.type) {
						return a;
					}
				}

				return null;
			}

			/** Numerical type for this algorithm constant. */
			public final int type;

			/**
			 * Instantiates a new algorithm.
			 * 
			 * @param type
			 *            the type
			 */
			private Algorithm(int type) {
				this.type = type;
			}
		}

		/**
		 * Specifies the checksum algorithm to be used.
		 * 
		 * @return type of algorithm
		 */
		@Field(offset = 2 * BYTE, length = 1 * BYTE)
		public int algorithm() {
			return getUByte(2);
		}

		/**
		 * Sets a new value for algorithm field.
		 * 
		 * @param value
		 *            new value to set
		 */
		public void algorithm(int value) {
			setUByte(2, value);
		}

		/**
		 * Returns the algorithm type as enum constant.
		 * 
		 * @return constant representing the algorithm or null if unrecognized
		 */
		public Algorithm algorithmEnum() {
			return Algorithm.valueOf(algorithm());
		}
	}

	/**
	 * A simple method for measuring the RTT of a segment would be: the sender
	 * places a timestamp in the segment and the receiver returns that timestamp
	 * in the corresponding ACK segment. When the ACK segment arrives at the
	 * sender, the difference between the current time and the timestamp is the
	 * RTT. To implement this timing method, the receiver must simply reflect or
	 * echo selected data (the timestamp) from the sender's segments. This idea
	 * is the basis of the "TCP Echo" and "TCP Echo Reply" options.
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 6)
	public static class Echo extends TcpOption {

		/**
		 * This option carries four bytes of information that the receiving TCP
		 * may send back in a subsequent TCP Echo Reply option (see below). A
		 * TCP may send the TCP Echo option in any segment, but only if a TCP
		 * Echo option was received in a SYN segment for the connection.
		 * <p>
		 * When the TCP echo option is used for RTT measurement, it will be
		 * included in data segments, and the four information bytes will define
		 * the time at which the data segment was transmitted in any format
		 * convenient to the sender.
		 * </p>
		 * 
		 * @return 4 bytes of information
		 */
		@Field(offset = 2 * BYTE, length = 4 * BYTE, format = "%x")
		public long data() {
			return getUInt(2);
		}
	}

	/**
	 * A TCP that receives a TCP Echo option containing four information bytes
	 * will return these same bytes in a TCP Echo Reply option.
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 7)
	public static class EchoReply extends TcpOption {

		/**
		 * This option carries four bytes of information that the receiving TCP
		 * may send back in a subsequent TCP Echo Reply option (see below). A
		 * TCP may send the TCP Echo option in any segment, but only if a TCP
		 * Echo option was received in a SYN segment for the connection.
		 * <p>
		 * When the TCP echo option is used for RTT measurement, it will be
		 * included in data segments, and the four information bytes will define
		 * the time at which the data segment was transmitted in any format
		 * convenient to the sender.
		 * </p>
		 * 
		 * @return 4 bytes of information
		 */
		@Field(offset = 2 * BYTE, length = 4 * BYTE, format = "%x")
		public long data() {
			return getUInt(2);
		}
	}

	/**
	 * Flags (8 bits) (aka Control bits) - contains 8 1-bit flags
	 * <ul>
	 * <li>CWR (1 bit) - Congestion Window Reduced (CWR) flag is set by the
	 * sending host to indicate that it received a TCP segment with the ECE flag
	 * set and had responded in congestion control mechanism (added to header by
	 * RFC 3168).
	 * <li>ECE (1 bit) - ECN-Echo indicates If the SYN flag is set, that the TCP
	 * peer is ECN capable. If the SYN flag is clear, that a packet with
	 * Congestion Experienced flag in IP header set is received during normal
	 * transmission (added to header by RFC 3168).
	 * <li>URG (1 bit) - indicates that the Urgent pointer field is significant
	 * <li>ACK (1 bit) - indicates that the Acknowledgment field is significant.
	 * All packets after the initial SYN packet sent by the client should have
	 * this flag set.
	 * <li>PSH (1 bit) - Push function. Asks to push the buffered data to the
	 * receiving application.
	 * <li>RST (1 bit) - Reset the connection
	 * <li>SYN (1 bit) - Synchronize sequence numbers. Only the first packet
	 * sent from each end should have this flag set. Some other flags change
	 * meaning based on this flag, and some are only valid for when it is set,
	 * and others when it is clear.
	 * <li>FIN (1 bit) - No more data from sender
	 * </ul>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Flag {
		/** 0 - FIN (1 bit) - No more data from sender. */
		FIN,

		/**
		 * 1 - SYN (1 bit) - Synchronize sequence numbers. Only the first packet
		 * sent from each end should have this flag set. Some other flags change
		 * meaning based on this flag, and some are only valid for when it is
		 * set, and others when it is clear.
		 */
		SYN,

		/** 2 - RST (1 bit) - Reset the connection. */
		RST,

		/**
		 * 3 - PSH (1 bit) - Push function. Asks to push the buffered data to
		 * the receiving application.
		 */
		PSH,

		/**
		 * 4 - ACK (1 bit) - indicates that the Acknowledgment field is
		 * significant. All packets after the initial SYN packet sent by the
		 * client should have this flag set.
		 */
		ACK,

		/**
		 * 5 - URG (1 bit) - indicates that the Urgent pointer field is
		 * significant.
		 */
		URG,

		/**
		 * 6 - ECE (1 bit) - ECN-Echo indicates If the SYN flag is set, that the
		 * TCP peer is ECN capable. If the SYN flag is clear, that a packet with
		 * Congestion Experienced flag in IP header set is received during
		 * normal transmission.
		 * 
		 * @see RFC3168
		 */
		ECE,

		/**
		 * 6 - CWR (1 bit) - Congestion Window Reduced (CWR) flag is set by the
		 * sending host to indicate that it received a TCP segment with the ECE
		 * flag set and had responded in congestion control mechanism.
		 * 
		 * @see RFC3168
		 */
		CWR,

		/**
		 * 8 - ECN-nonce concealment protection
		 * 
		 * @see RFC3540
		 */
		NS,

		/* END OF FLAGS */
		;
		/**
		 * Converts 8 contigeous bits of an inteteger to a set collection of
		 * enum constants, each representing if a flag is set in the original
		 * integer.
		 * 
		 * @param flags
		 *            integer containing the flags (8-bits)
		 * @return a collection set with constants for each bit set within the
		 *         integer
		 */
		public static Set<Flag> asSet(final int flags) {
			final Set<Flag> set = EnumSet.noneOf(Tcp.Flag.class);
			final int len = values().length;

			for (int i = 0; i < len; i++) {
				if ((flags & (1 << i)) > 0) {
					set.add(values()[i]);
				}
			}

			return set;
		}

		/**
		 * Returns a compact string representation of the bit flags that are set
		 * within the integer.
		 * 
		 * @param flags
		 *            integer containing the flags (8-bit)
		 * @return a terse representation of the flags
		 */
		public static String toCompactString(final int flags) {
			return toCompactString(asSet(flags));
		}

		/**
		 * Returns a compact string representation of the flags contained with
		 * the collection's set.
		 * 
		 * @param flags
		 *            a collection's set of flags
		 * @return a terse representation of the flags
		 */
		public static String toCompactString(final Set<Flag> flags) {
			final StringBuilder b = new StringBuilder(values().length);
			for (final Flag f : flags) {
				b.append(f.name().charAt(0));
			}

			return b.toString();
		}
	}

	/**
	 * The TCP Maximum Segment Size option can be used to specify the maximum
	 * segment size that the receiver should use.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 2, description = "Maximum Segment Size")
	public static class MSS extends TcpOption {

		/**
		 * This field must only be sent in the initial connection request (i.e.,
		 * in segments with the SYN control bit set). If this option is not
		 * used, any segment size is allowed.
		 * 
		 * @return value of the field
		 */
		@Field(offset = 2 * BYTE, length = 2 * BYTE)
		public int mss() {
			return getUShort(2);
		}

		/**
		 * Sets a new value in the field.
		 * 
		 * @param value
		 *            new field value
		 */
		public void mss(int value) {
			setUShort(2, value);
		}
	}

	/**
	 * No operation. Consumes 1 byte. Used for aligning and padding.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 1)
	public static class NoOp extends TcpOption {
	}

	/**
	 * Serves to communicate the information necessary to carry out the job of
	 * the protocol - the type of information which is typically found in the
	 * header of a TCP segment.
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 10)
	public static class PartialOrderConnection extends TcpOption {

		/**
		 * This option carries four bytes of information that the receiving TCP
		 * may send back in a subsequent TCP Echo Reply option (see below). A
		 * TCP may send the TCP Echo option in any segment, but only if a TCP
		 * Echo option was received in a SYN segment for the connection.
		 * <p>
		 * When the TCP echo option is used for RTT measurement, it will be
		 * included in data segments, and the four information bytes will define
		 * the time at which the data segment was transmitted in any format
		 * convenient to the sender.
		 * </p>
		 * 
		 * see RFC 1693
		 * 
		 * @return 4 bytes of information
		 */
		@Field(offset = 2 * BYTE, length = 1 * BYTE, format = "%x")
		public int options() {
			return getUByte(2);
		}

		/**
		 * Options_ end.
		 * 
		 * @return the int
		 */
		@Field(parent = "options", offset = 1, length = 1)
		public int options_End() {
			return (options() & 0x02) >> 1;
		}

		/**
		 * Options_ filler.
		 * 
		 * @return the int
		 */
		@Field(parent = "options", offset = 2, length = 6)
		public int options_Filler() {
			return (options() & 0xFA) >> 2;
		}

		/**
		 * Options_ start.
		 * 
		 * @return the int
		 */
		@Field(parent = "options", offset = 0, length = 1)
		public int options_Start() {
			return options() & 0x01;
		}
	}

	/**
	 * A service which allows partial order delivery and partial reliability is
	 * one which requires some, but not all objects to be received in the order
	 * transmitted while also allowing objects to be transmitted unreliably
	 * (i.e., some may be lost).
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 9)
	public static class PartialOrderConnectionPermitted extends TcpOption {
		// No other fields
	}

	/**
	 * TCP may experience poor performance when multiple packets are lost from
	 * one window of data. With the limited information available from
	 * cumulative acknowledgments, a TCP sender can only learn about a single
	 * lost packet per round trip time. An aggressive sender could choose to
	 * retransmit packets early, but such retransmitted segments may have
	 * already been successfully received.
	 * <p>
	 * SACK is a strategy which corrects this behavior in the face of multiple
	 * dropped segments. With selective acknowledgments, the data receiver can
	 * inform the sender about all segments that have arrived successfully, so
	 * the sender need retransmit only the segments that have actually been
	 * lost.
	 * </p>
	 * <p>
	 * The SACK option is to be sent by a data receiver to inform the data
	 * sender of non-contiguous blocks of data that have been received and
	 * queued. The data receiver awaits the receipt of data (perhaps by means of
	 * retransmissions) to fill the gaps in sequence space between received
	 * blocks. When missing segments are received, the data receiver
	 * acknowledges the data normally by advancing the left window edge in the
	 * Acknowledgement Number Field of the TCP header. The SACK option does not
	 * change the meaning of the Acknowledgement Number field.
	 * </p>
	 * <p>
	 * This note defines an extension of the SACK option for TCP. RFC 2018
	 * specified the use of the SACK option for acknowledging out-of-sequence
	 * data not covered by TCP's cumulative acknowledgement field. This note
	 * extends RFC 2018 by specifying the use of the SACK option for
	 * acknowledging duplicate packets. This note suggests that when duplicate
	 * packets are received, the first block of the SACK option field can be
	 * used to report the sequence numbers of the packet that triggered the
	 * acknowledgement. This extension to the SACK option allows the TCP sender
	 * to infer the order of packets received at the receiver, allowing the
	 * sender to infer when it has unnecessarily retransmitted a packet. A TCP
	 * sender could then use this information for more robust operation in an
	 * environment of reordered packets, ACK loss, packet replication, and/or
	 * early retransmit timeouts.
	 * </p>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 5)
	public static class SACK extends TcpOption {

		/**
		 * Calculates the number of SACK blocks within this option header.
		 * 
		 * @return number of 64 bit blocks
		 */
		public int blockCount() {
			return (size() - 2) / 8; // (block_size) div 64-bit-block-length
		}

		/**
		 * Gets the block field of the option header, and returns the data as an
		 * array of unsigned 32 bit integers (java stored as long integers to
		 * preserve the sign). Each element of the array, is a 1 element of the
		 * 2 element block. The even elements starting at index 0 are start
		 * sequence numbers, while the odd elements starting at index 1 are the
		 * ending sequence numbers past the last acked byte in the stream.
		 * 
		 * @return blocks field data converted to longs to represent a 32 bit
		 *         unsigned integer
		 */
		@Field(offset = 2 * BYTE)
		public long[] blocks() {
			return blocksToArray(new long[blockCount() * 2]);
		}

		/**
		 * Copies the supplied data in the array to option header. The method
		 * also updates the option header length field overriding any previously
		 * set value there.
		 * 
		 * @param array
		 *            array containing the block records
		 */
		public void blocks(long[] array) {
			final int count = array.length / 2;

			for (int i = 0; i < count; i++) {
				setUInt(i * 4 + 2, array[i]);
			}

			/*
			 * Updata the option length field
			 */
			length(array.length * 4 + 2);
		}

		/**
		 * Calculates the length of the block field.
		 * 
		 * @return length of the field in bits
		 */
		@Dynamic(Field.Property.LENGTH)
		public int blocksLength() {
			return blockCount() * 64; // In bits
		}

		/**
		 * Gets the block field of the option header, and returns the data as an
		 * array of unsigned 32 bit integers (java stored as long integers to
		 * preserve the sign). Each element of the array, is a 1 element of the
		 * 2 element block. The even elements starting at index 0 are start
		 * sequence numbers, while the odd elements starting at index 1 are the
		 * ending sequence numbers past the last acked byte in the stream.
		 * 
		 * @param array
		 *            preallocated array to store the data
		 * @return the array supplied as argument
		 */
		public long[] blocksToArray(long[] array) {
			final int count =
					(array.length < blockCount() * 2)
							? array.length
							: blockCount() * 2;

			for (int i = 0; i < count; i++) {
				array[i] = getUInt(i * 4 + 2);
			}

			return array;
		}
	}

	/**
	 * The TCP SACK permitted option may be sent in a SYN by a TCP that has been
	 * extended to receive the SACK option once the connection has opened. It
	 * MUST NOT be sent on non-SYN segments.
	 * <p>
	 * This option has no fields. Its presence determines if TCP SACK is
	 * permitted.
	 * </p>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 4)
	public static class SACK_PERMITTED extends TcpOption {
	}

	/**
	 * Options (Variable 0-320 bits, divisible by 32) - The length of this field
	 * is determined by the data offset field. Options 0 and 1 are a single byte
	 * (8 bits) in length. The remaining options indicate the total length of
	 * the option (expressed in bytes) in the second byte. Some options may only
	 * be sent when SYN is set;
	 * <ul>
	 * <li>0 (8 bits) - End of options list
	 * <li>1 (8 bits) - No operation (NOP, Padding) This may be used to align
	 * option fields on 32-bit boundaries for better performance.
	 * <li>2,4,SS (32 bits) - Maximum segment size (see maximum segment size)
	 * [SYN]
	 * <li>3,3,S (24 bits) - Window scale (see window scaling for details) [SYN]
	 * <li>4,2 (16 bits) - Selective Acknowledgement permitted. [SYN] (See
	 * selective acknowledgments for details)
	 * <li>5,N,BBBB,EEEE,... (variable bits, N is either 10, 18, 26, or 34)-
	 * Selective ACKnowlegement (SACK) These first two bytes are followed by a
	 * list of 1-4 blocks being selectively acknowledged, specified as 32-bit
	 * begin/end pointers.
	 * <li>8,10,TTTT,EEEE (80 bits)- Timestamp and echo of previous timestamp
	 * (see TCP Timestamps for details)
	 * <li>14,3,S (24 bits) - TCP Alternate Checksum Request. [SYN]
	 * <li>15,N,... (variable bits) - TCP Alternate Checksum Data.
	 * </ul>
	 * </ul>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class TcpOption extends JSubHeader<Tcp> {

		/**
		 * Calculates the length of a tcp option header.
		 * 
		 * @param buffer
		 *            buffer containing tcp option header data
		 * @param offset
		 *            offset into the buffer where tcp option header start (in
		 *            bytes)
		 * @return number of bytes occupied by the tcp header, including any tcp
		 *         options
		 */
		@HeaderLength
		public static int headerLength(final JBuffer buffer, final int offset) {
			return buffer.getUByte(offset + 1);
		}

		/**
		 * Options (Variable 0-320 bits, divisible by 32) - The length of this
		 * field is determined by the data offset field. Options 0 and 1 are a
		 * single byte (8 bits) in length. The remaining options indicate the
		 * total length of the option (expressed in bytes) in the second byte.
		 * Some options may only be sent when SYN is set;
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum OptionCode {

			/**
			 * 15,N,... (variable bits) - TCP Alternate Checksum Data.
			 */
			ALTERNATE_CHECKSUM(15),
			/**
			 * 14,3,S (24 bits) - TCP Alternate Checksum Request. [SYN]
			 */
			ALTERNATE_CHECKSUM_REQUEST(14),

			/**
			 * This option carries four bytes of information that the receiving
			 * TCP may send back in a subsequent TCP Echo Reply option (see
			 * below). A TCP may send the TCP Echo option in any segment, but
			 * only if a TCP Echo option was received in a SYN segment for the
			 * connection.
			 */
			ECHO(6),

			/** Returns the 4 bytes of ECHO data. */
			ECHO_REPLY(7),

			/** 0 (8 bits) - End of options list. */
			END_OF_OPTION_LIST(0),

			/**
			 * 2,4,SS (32 bits) - Maximum segment size (see maximum segment
			 * size) [SYN].
			 */
			MAXIMUM_SEGMENT_SIZE(2),

			/**
			 * 1 (8 bits) - No operation (NOP, Padding) This may be used to
			 * align option fields on 32-bit boundaries for better performance.
			 */
			NO_OP(1),

			/**
			 * Partial order connection data
			 */
			PARTIAL_ORDER_CONNECTION(10),

			/**
			 * Partial order connection permitted flag
			 */
			PARTIAL_ORDER_CONNECTION_PERMITTED(9),

			/**
			 * 5,N,BBBB,EEEE,... (variable bits, N is either 10, 18, 26, or 34)-
			 * Selective ACKnowlegement (SACK) These first two bytes are
			 * followed by a list of 1-4 blocks being selectively acknowledged,
			 * specified as 32-bit begin/end pointers.
			 */
			SACK(5),
			/**
			 * 4,2 (16 bits) - Selective Acknowledgement permitted. [SYN]
			 */
			SACK_PERMITTED(4),

			/**
			 * 8,10,TTTT,EEEE (80 bits)- Timestamp and echo of previous
			 * timestamp.
			 */
			TIMESTAP(8),

			/**
			 * 3,3,S (24 bits) - Window scale (see window scaling for details)
			 * [SYN].
			 */
			WINDOW_SCALE(3)

			;

			/**
			 * Converts a numerical op code to a enum constant.
			 * 
			 * @param id
			 *            numerical constant to convert
			 * @return enum constant
			 */
			public static OptionCode valueOf(int id) {
				for (OptionCode c : values()) {
					if (c.id == id) {
						return c;
					}
				}

				return null;
			}

			/** OP CODE for this option. */
			public final int id;

			/**
			 * Initialize to static op code.
			 * 
			 * @param id
			 *            the id
			 */
			private OptionCode(int id) {
				this.id = id;
			}

		}

		/**
		 * Option header op-code (8 bits).
		 * 
		 * @return numerical code for this field
		 */
		@Field(offset = 0 * BYTE, length = 1 * BYTE)
		public int code() {
			return getUByte(0);
		}

		/**
		 * Sets the ption header op-code (8 bits).
		 * 
		 * @param value
		 *            new numerical code for this field
		 */
		public void code(int value) {
			setUByte(0, value);
		}

		/**
		 * Optional length of this option. Some options have implied length of 1
		 * (NoOP and END_OF_OPTIONS), while the rest of Tcp options supply the
		 * length of the option, including the code and length fields
		 * themselves.
		 * 
		 * @return number of bytes this option occupies, or 1 of implied
		 */
		@Field(offset = 1 * BYTE, length = 1 * BYTE)
		public int length() {
			return lengthCheck(null) ? getUByte(1) : 1;
		}

		/**
		 * Sets a new length for the option.
		 * 
		 * @param value
		 *            new length in bytes to be stored in length field
		 */
		public void length(int value) {
			setUByte(1, value);
		}

		/**
		 * A runtime check if the length field is present in the option or if
		 * length of 1 is implied by option type.
		 * 
		 * @param name
		 *            ignored
		 * @return true if length field is present, otherwise false if length
		 *         field is not present but implied
		 */
		@Dynamic(field = "length", value = Field.Property.CHECK)
		public boolean lengthCheck(String name) {
			return (code() > 1); // Only 0 and 1 don't have length field
		}

		/**
		 * Dynamically generates additional description information.
		 * 
		 * @return description of the field or null if not implied length
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String lengthDescription() {
			return lengthCheck(null) ? null : "implied length from option type";
		}
	}

	/**
	 * TCP timestamps, defined in RFC 1323, help TCP compute the round-trip time
	 * between the sender and receiver. Timestamp options include a 4-byte
	 * timestamp value, where the sender inserts its current value of its
	 * timestamp clock, and a 4-byte echo reply timestamp value, where the
	 * receiver generally inserts the most recent timestamp value that it has
	 * received. The sender uses the echo reply timestamp in an acknowledgment
	 * to compute the total elapsed time since the acknowledged segment was
	 * sent.[2]
	 * <p>
	 * TCP timestamps are also used to help in the case where TCP sequence
	 * numbers encounter their 232 bound and "wrap around" the sequence number
	 * space. This scheme is known as Protect Against Wrapped Sequence numbers,
	 * or PAWS (see RFC 1323 for details). Furthermore, the Eifel detection
	 * algorithm, defined in RFC 3522, which detects unnecessary loss recovery
	 * requires TCP timestamps.
	 * </p>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 8)
	public static class Timestamp extends TcpOption {

		/**
		 * This field is only valid if the ACK bit is set in the TCP header. If
		 * it is valid, it echos a timestamp value that was sent by the remote
		 * TCP in the TSval field of a Timestamps option. When TSecr is not
		 * valid, its value must be zero. The TSecr value will generally be from
		 * the most recent Timestamp option that was received; A TCP may send
		 * the Timestamp option in an initial SYN segment (i.e., segment
		 * containing a SYN bit and no ACK bit), and may send a TSopt in other
		 * segments only if it received a TSopt in the initial SYN segment for
		 * the connection.
		 * 
		 * @return timestamp value
		 */
		@Field(offset = 6 * BYTE, length = 4 * BYTE)
		public long tsecr() {
			return getUInt(6);
		}

		/**
		 * Sets the field's value.
		 * 
		 * @param value
		 *            new field value
		 */
		public void tsecr(long value) {
			setUInt(6, value);
		}

		/**
		 * This field contains the current value of the timestamp clock of the
		 * TCP sending the option (32 bits).
		 * 
		 * @return field's value
		 */
		@Field(offset = 2 * BYTE, length = 4 * BYTE)
		public long tsval() {
			return getUInt(2);
		}

		/**
		 * Sets the field's value.
		 * 
		 * @param value
		 *            new field value
		 */
		public void tsval(long value) {
			setUInt(2, value);
		}
	}

	/**
	 * The window scale extension expands the definition of the TCP window to 32
	 * bits and then uses a scale factor to carry this 32 bit value in the 16
	 * bit Window field of the TCP header (SEG.WND in RFC-793). The scale factor
	 * is carried in a new TCP option, Window Scale. This option is sent only in
	 * a SYN segment (a segment with the SYN bit on), hence the window scale is
	 * fixed in each direction when a connection is opened. (Another design
	 * choice would be to specify the window scale in every TCP segment. It
	 * would be incorrect to send a window scale option only when the scale
	 * factor changed, since a TCP option in an acknowledgement segment will not
	 * be delivered reliably (unless the ACK happens to be piggy-backed on data
	 * in the other direction). Fixing the scale when the connection is opened
	 * has the advantage of lower overhead but the disadvantage that the scale
	 * factor cannot be changed during the connection.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 3)
	public static class WindowScale extends TcpOption {

		/**
		 * The window scale extension expands the definition of the TCP window
		 * to 32 bits and then uses a scale factor to carry this 32 bit value in
		 * the 16 bit Window field of the TCP header (SEG.WND in RFC-793). The
		 * scale factor is carried in a new TCP option, Window Scale. This
		 * option is sent only in a SYN segment (a segment with the SYN bit on),
		 * hence the window scale is fixed in each direction when a connection
		 * is opened. (Another design choice would be to specify the window
		 * scale in every TCP segment. It would be incorrect to send a window
		 * scale option only when the scale factor changed, since a TCP option
		 * in an acknowledgement segment will not be delivered reliably (unless
		 * the ACK happens to be piggy-backed on data in the other direction).
		 * Fixing the scale when the connection is opened has the advantage of
		 * lower overhead but the disadvantage that the scale factor cannot be
		 * changed during the connection.
		 * <p>
		 * The three-byte Window Scale option may be sent in a SYN segment by a
		 * TCP. It has two purposes: (1) indicate that the TCP is prepared to do
		 * both send and receive window scaling, and (2) communicate a scale
		 * factor to be applied to its receive window. Thus, a TCP that is
		 * prepared to scale windows should send the option, even if its own
		 * scale factor is 1. The scale factor is limited to a power of two and
		 * encoded logarithmically, so it may be implemented by binary shift
		 * operations.
		 * </p>
		 * 
		 * @return scaling factor for window scale
		 */
		@Field(offset = 2 * BYTE, length = 1 * BYTE)
		public int scale() {
			return getUByte(2);
		}

		/**
		 * Sets a new scaling factor.
		 * 
		 * @param value
		 *            value to set in the field
		 */
		public void scale(int value) {
			setUByte(2, value);
		}
	}

	/** The Constant FLAG_ACK. */
	private static final int FLAG_ACK = 0x10;

	/** The Constant FLAG_CONG. */
	private static final int FLAG_CONG = 0x80;

	/** The Constant FLAG_CWR. */
	private static final int FLAG_CWR = 0x80;

	/** The Constant FLAG_ECE. */
	private static final int FLAG_ECE = 0x40;

	/** The Constant FLAG_ECN. */
	private static final int FLAG_ECN = 0x40;

	/** The Constant FLAG_FIN. */
	private static final int FLAG_FIN = 0x01;

	/** The Constant FLAG_PSH. */
	private static final int FLAG_PSH = 0x08;

	/** The Constant FLAG_RST. */
	private static final int FLAG_RST = 0x04;

	/** The Constant FLAG_SYN. */
	private static final int FLAG_SYN = 0x02;

	/** The Constant FLAG_URG. */
	private static final int FLAG_URG = 0x20;

	/** Unique numerical ID for this protocol header definition. */
	public static final int ID = JProtocol.TCP_ID;

	/**
	 * Calculates the length of a tcp header.
	 * 
	 * @param buffer
	 *            buffer containing packet and/or tcp header data
	 * @param offset
	 *            offset into the buffer where tcp header start (in bytes)
	 * @return number of bytes occupied by the tcp header, including any tcp
	 *         options
	 */
	@HeaderLength
	public static int headerLength(final JBuffer buffer, final int offset) {
		final int hlen = (buffer.getUByte(offset + 12) & 0xF0) >> 4;
		return hlen * 4;
	}

	/** Hashcode computed. */
	private int biDirectionalHashcode;

	/** The ip. */
	private final Ip4 ip4 = new Ip4();
	private final Ip6 ip6 = new Ip6();

	/**
	 * Computed in decodeHeader. The hashcode is made up of IP address and port
	 * number using only the destination addresses. This creates a hashcode that
	 * is unique in a single direction.
	 */
	private int uniDirectionalHashcode;

	/**
	 * Acknowledgment number (32 bits). If the ACK flag is set then the value of
	 * this field is the next sequence number that the receiver is expecting.
	 * This acknowledges receipt of all prior bytes (if any). The first ACK sent
	 * by each end acknowledges the other end's initial sequence number itself,
	 * but no data.
	 * 
	 * @return the value of the field
	 */
	@Field(offset = 8 * BYTE, length = 16, format = "%x")
	public long ack() {
		return getUInt(8);
	}

	/**
	 * Ack.
	 * 
	 * @param ack
	 *            the ack
	 */
	public void ack(final long ack) {
		super.setUInt(8, ack);
	}

	/**
	 * Calculates a checksum using protocol specification for a header.
	 * Checksums for partial headers or fragmented packets (unless the protocol
	 * alows it) are not calculated.
	 * 
	 * @return header's calculated checksum
	 */
	public int calculateChecksum() {

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.inChecksumShouldBe(checksum(),
				Checksum.pseudoTcp(this.packet, ipOffset, getOffset()));
	}

	/**
	 * Checksum (16 bits). The 16-bit checksum field is used for error-checking
	 * of the header and data .
	 * 
	 * @return the field's value
	 */
	@Field(offset = 16 * BYTE, length = 16, format = "%x")
	public int checksum() {
		return getUShort(16);
	}

	/**
	 * Checksum.
	 * 
	 * @param crc
	 *            the crc
	 */
	public boolean checksum(final int crc) {
		super.setUShort(16, crc);

		return true;
	}

	/**
	 * Returns a dynamic description of the checksum field. Specifically it
	 * checks and displays, as description, the state of the checksum field, if
	 * it matches the calculated checksum or not.
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

		final int crc16 = calculateChecksum();
		if (checksum() == crc16) {
			return "correct";
		} else {
			return "incorrect: 0x" + Integer.toHexString(crc16).toUpperCase();
		}
	}

	/**
	 * Clear flag.
	 * 
	 * @param flag
	 *            the flag
	 */
	private void clearFlag(int flag) {
		super.setUByte(13, flags() & ~flag);

	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeader#getPayload()
	 */
	@Override
	public byte[] getPayload() {
		// TODO Auto-generated method stub
		return super.getPayload();
	}

	/**
	 * Decode header.
	 * 
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {
		/*
		 * Generate a bi-directional hashcode
		 */
		if ((getPacket() != null) && getPacket().hasHeader(this.ip4)) {
			this.biDirectionalHashcode =
					(this.ip4.destinationToInt() + destination())
							^ (this.ip4.sourceToInt() + source());

			this.uniDirectionalHashcode =
					(this.ip4.destinationToInt() + destination());

		} else if ((getPacket() != null) && getPacket().hasHeader(this.ip6) ) {
			this.biDirectionalHashcode =
					(this.ip6.destinationToIntHash() + destination())
							^ (this.ip6.sourceToIntHash() + source());

			this.uniDirectionalHashcode =
					(this.ip6.destinationToIntHash() + destination());
		} else {
			this.biDirectionalHashcode = super.hashCode();
		}

		optionsBitmap = 0;

		// System.out.printf("offset=%d, %s %s", getOffset(),
		// getPacket().getState()
		// .toDebugString(), toHexdump());
		final int hlen = hlen() * 4;

		for (int i = 20, p = 0; i < hlen && i != p; i++, p = i) {
			final int id = getUByte(i);
			if (id >= optionsOffsets.length) {

				i += getUByte(i + 1); // Skip to next option
				break;
			}
			optionsOffsets[id] = i;
			optionsBitmap |= (1 << id);

			final TcpOption.OptionCode code = TcpOption.OptionCode.valueOf(id);

			/*
			 * Handle all new options we haven't defined yet
			 */
			if (code == null) {
				final int length = getUByte(i + 1); // Length option field
				i += length - 1;
				optionsLength[id] = length;
				continue;
			}

			// System.out.printf("%s: i=%d id=%d ", code, i, id);
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
				// System.out.printf("length=%d", length);
				i += length - 1;
				optionsLength[id] = length;
				break;
			}

			// System.out.println();
			// System.out.printf("i=%d id=%d bitmap=0x%X length=%d\n", i, id,
			// optionsBitmap, optionsLength[id]);
		}

	}

	/**
	 * Destination port (16 bits). Identifies the receiving port
	 * 
	 * @return the field's value
	 */
	@BindingVariable
	@Field(offset = 16, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int destination() {
		return getUShort(2);
	}

	/**
	 * Sets a new value for the destination field.
	 * 
	 * @param value
	 *            new value for the field
	 */
	public void destination(final int value) {
		super.setUShort(2, value);
	}

	/**
	 * Flags (8 bits) (aka Control bits) - contains 8 1-bit flags
	 * <ul>
	 * <li>CWR (1 bit) - Congestion Window Reduced (CWR) flag is set by the
	 * sending host to indicate that it received a TCP segment with the ECE flag
	 * set and had responded in congestion control mechanism (added to header by
	 * RFC 3168).
	 * <li>ECE (1 bit) - ECN-Echo indicates If the SYN flag is set, that the TCP
	 * peer is ECN capable. If the SYN flag is clear, that a packet with
	 * Congestion Experienced flag in IP header set is received during normal
	 * transmission (added to header by RFC 3168).
	 * <li>URG (1 bit) - indicates that the Urgent pointer field is significant
	 * <li>ACK (1 bit) - indicates that the Acknowledgment field is significant.
	 * All packets after the initial SYN packet sent by the client should have
	 * this flag set.
	 * <li>PSH (1 bit) - Push function. Asks to push the buffered data to the
	 * receiving application.
	 * <li>RST (1 bit) - Reset the connection
	 * <li>SYN (1 bit) - Synchronize sequence numbers. Only the first packet
	 * sent from each end should have this flag set. Some other flags change
	 * meaning based on this flag, and some are only valid for when it is set,
	 * and others when it is clear.
	 * <li>FIN (1 bit) - No more data from sender
	 * </ul>
	 * 
	 * @return the field's value
	 */
	@Field(offset = 13 * BYTE, length = 8, format = "%x")
	public int flags() {
		return getUByte(13);
	}

	/**
	 * Sets a new value for the flags field (8-bits).
	 * 
	 * @param value
	 *            new value for the field
	 */
	public void flags(final int value) {
		super.setUByte(13, value);
	}

	/**
	 * ACK (1 bit) - indicates that the Acknowledgment field is significant. All
	 * packets after the initial SYN packet sent by the client should have this
	 * flag set.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(
			parent = "flags",
			offset = 4,
			length = 1,
			format = "%b",
			display = "ack",
			description = "acknowledgment")
	public boolean flags_ACK() {
		return (flags() & FLAG_ACK) != 0;
	}

	/**
	 * Sets new value for the bit flag.
	 * 
	 * @param value
	 *            sets the flag bit, false clears it
	 */
	public void flags_ACK(final boolean value) {
		setFlag(value, FLAG_ACK);
	}

	/**
	 * CWR (1 bit) - Congestion Window Reduced (CWR) flag is set by the sending
	 * host to indicate that it received a TCP segment with the ECE flag set and
	 * had responded in congestion control mechanism (added to header by RFC
	 * 3168).
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(
			parent = "flags",
			offset = 7,
			length = 1,
			format = "%b",
			display = "cwr",
			description = "reduced (cwr)")
	public boolean flags_CWR() {
		return (flags() & FLAG_CWR) != 0;
	}

	/**
	 * Sets new value for the bit flag.
	 * 
	 * @param value
	 *            sets the flag bit, false clears it
	 */
	public void flags_CWR(final boolean value) {
		setFlag(value, FLAG_CWR);
	}

	/**
	 * ECE (1 bit) - ECN-Echo indicates If the SYN flag is set, that the TCP
	 * peer is ECN capable. If the SYN flag is clear, that a packet with
	 * Congestion Experienced flag in IP header set is received during normal
	 * transmission (added to header by RFC 3168).
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(
			parent = "flags",
			offset = 6,
			length = 1,
			format = "%b",
			display = "ece",
			description = "ECN echo flag")
	public boolean flags_ECE() {
		return (flags() & FLAG_ECE) != 0;
	}

	/**
	 * Sets new value for the bit flag.
	 * 
	 * @param value
	 *            sets the flag bit, false clears it
	 */
	public void flags_ECE(final boolean value) {
		setFlag(value, FLAG_ECE);
	}

	/**
	 * FIN (1 bit) - No more data from sender.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(
			parent = "flags",
			offset = 0,
			length = 1,
			format = "%b",
			display = "fin",
			description = "closing down connection")
	public boolean flags_FIN() {
		return (flags() & FLAG_FIN) != 0;
	}

	/**
	 * Sets new value for the bit flag.
	 * 
	 * @param value
	 *            sets the flag bit, false clears it
	 */
	public void flags_FIN(final boolean value) {
		setFlag(value, FLAG_FIN);
	}

	/**
	 * PSH (1 bit) - Push function. Asks to push the buffered data to the
	 * receiving application.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(
			parent = "flags",
			offset = 3,
			length = 1,
			format = "%b",
			display = "ack",
			description = "push current segment of data")
	public boolean flags_PSH() {
		return (flags() & FLAG_PSH) != 0;
	}

	/**
	 * Sets new value for the bit flag.
	 * 
	 * @param value
	 *            sets the flag bit, false clears it
	 */
	public void flags_PSH(final boolean value) {
		setFlag(value, FLAG_PSH);
	}

	/**
	 * RST (1 bit) - Reset the connection.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(
			parent = "flags",
			offset = 2,
			length = 1,
			format = "%b",
			display = "ack",
			description = "reset connection")
	public boolean flags_RST() {
		return (flags() & FLAG_RST) != 0;
	}

	/**
	 * Sets new value for the bit flag.
	 * 
	 * @param value
	 *            sets the flag bit, false clears it
	 */
	public void flags_RST(final boolean value) {
		setFlag(value, FLAG_RST);
	}

	/**
	 * SYN (1 bit) - Synchronize sequence numbers. Only the first packet sent
	 * from each end should have this flag set. Some other flags change meaning
	 * based on this flag, and some are only valid for when it is set, and
	 * others when it is clear.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(
			parent = "flags",
			offset = 1,
			length = 1,
			format = "%b",
			display = "ack",
			description = "synchronize connection, startup")
	public boolean flags_SYN() {
		return (flags() & FLAG_SYN) != 0;
	}

	/**
	 * Sets new value for the bit flag.
	 * 
	 * @param value
	 *            sets the flag bit, false clears it
	 */
	public void flags_SYN(final boolean value) {
		setFlag(value, FLAG_SYN);
	}

	/**
	 * URG (1 bit) - indicates that the Urgent pointer field is significant.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(
			parent = "flags",
			offset = 5,
			length = 1,
			format = "%b",
			display = "ack",
			description = "urgent, out-of-band data")
	public boolean flags_URG() {
		return (flags() & FLAG_URG) != 0;
	}

	/**
	 * Sets new value for the bit flag.
	 * 
	 * @param value
	 *            sets the flag bit, false clears it
	 */
	public void flags_URG(final boolean value) {
		setFlag(value, FLAG_URG);
	}

	/**
	 * Returns a compact string representation of the flags contained within
	 * flags field.
	 * 
	 * @return a terse representation of the flags
	 */
	public String flagsCompactString() {
		return Flag.toCompactString(flags());
	}

	/**
	 * Retruns a collection set representation of the flags contained within the
	 * flags field.
	 * 
	 * @return a collection set of the flags field
	 */
	public Set<Flag> flagsEnum() {
		return Flag.asSet(flags());
	}

	/**
	 * Returns a bi-directional hashcode for this header. The hashcode is made
	 * up of IP source, IP destination, Tcp source and destination port numbers.
	 * It is created in a such a way that packet's source and destination fields
	 * are interchangable and will generate the same hashcode.
	 * 
	 * @return bi-directional hashcode for this TCP/IP header combination
	 * @see #uniHashCode()
	 */
	@Override
	public int hashCode() {
		return this.biDirectionalHashcode;
	}

	/**
	 * Data offset (4 bits). Specifies the size of the TCP header in 32-bit
	 * words. The minimum size header is 5 words and the maximum is 15 words
	 * thus giving the minimum size of 20 bytes and maximum of 60 bytes,
	 * allowing for up to 40 bytes of options in the header. This field gets its
	 * name from the fact that it is also the offset from the start of the TCP
	 * segment to the actual data.
	 * 
	 * @return the field's value
	 */
	@Field(offset = 12 * BYTE, length = 4)
	public int hlen() {
		return (getUByte(12) & 0xF0) >> 4;
	}

	/**
	 * Hlen.
	 * 
	 * @param length
	 *            in 4 byte words
	 */
	public void hlen(final int length) {
		super.setUByte(12, ((getUByte(12) & 0x0F) | (length << 4)));
	}

	/**
	 * Checks if the checksum is valid, for un-fragmented packets. If a packet
	 * is fragmented, the checksum is not verified as data to is incomplete, but
	 * the method returns true none the less.
	 * 
	 * @return true if checksum checks out or if this is a fragment, otherwise
	 *         if the computed checksum does not match the stored checksum false
	 *         is returned
	 */
	public boolean isChecksumValid() {

		if (isFragmented()) {
			return true;
		}

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.pseudoTcp(this.packet, ipOffset, getOffset()) == 0;
	}

	/**
	 * Method which recomputes the checksum and sets the new computed value in
	 * checksum field.
	 * 
	 * @return true if setter succeeded, or false if unable to set the checksum
	 *         such as when its the case when header is truncated or not
	 *         complete
	 * @see org.jnetpcap.packet.JHeaderChecksum#recalculateChecksum()
	 */
	@Override
	public boolean recalculateChecksum() {
		return checksum(calculateChecksum());
	}

	/**
	 * Reserved (4 bits). For future use and should be set to zero.
	 * 
	 * @return the field's value
	 */
	@Field(offset = 12 * BYTE + 4, length = 4)
	public int reserved() {
		return getUByte(12) & 0x0F;
	}

	/**
	 * Sets a new value for the field.
	 * 
	 * @param value
	 *            new value (4 bits)
	 */
	public void reserved(final int value) {
		setUByte(12, value & 0x0F);
	}

	/**
	 * Sequence number (32 bits). Has a dual role:
	 * <ul>
	 * <li>If the SYN flag is set, then this is the initial sequence number. The
	 * sequence number of the actual first data byte (and the acknowledged
	 * number in the corresponding ACK) are then this sequence number plus 1.
	 * <li>If the SYN flag is clear, then this is the accumulated sequence
	 * number of the first data byte of this packet for the current session.
	 * </ul>
	 * 
	 * @return the field's value
	 */
	@Field(offset = 4 * BYTE, length = 16, format = "%x")
	public long seq() {
		return getUInt(4);
	}

	/**
	 * Seq.
	 * 
	 * @param seq
	 *            the seq
	 */
	public void seq(final long seq) {
		super.setUInt(4, seq);
	}

	/**
	 * Sets the flag.
	 * 
	 * @param state
	 *            the state
	 * @param flag
	 *            the flag
	 */
	private void setFlag(final boolean state, final int flag) {
		if (state) {
			setFlag(flag);
		} else {
			clearFlag(flag);
		}
	}

	/**
	 * Sets the flag.
	 * 
	 * @param flag
	 *            the new flag
	 */
	private void setFlag(final int flag) {
		super.setUByte(13, flags() | flag);
	}

	/**
	 * Source port (16 bits). Identifies the sending port.
	 * 
	 * @return the field's value
	 */
	@BindingVariable
	@Field(offset = 0, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int source() {
		return getUShort(0);
	}

	/**
	 * Sets a new value for the field (16 bits).
	 * 
	 * @param src
	 *            new value (16 bits)
	 */
	public void source(final int src) {
		super.setUShort(0, src);
	}

	/**
	 * Uni-directional hashcode. A hashcode that is computed based on IP
	 * destination and TCP destination port. This make the hashcode
	 * uni-direction in the direction from source to destination.
	 * 
	 * @return a hashcode that is uni-directional
	 */
	public int uniHashCode() {
		return this.uniDirectionalHashcode;
	}

	/**
	 * Urgent pointer (16 bits). If the URG flag is set, then this 16-bit field
	 * is an offset from the sequence number indicating the last urgent data
	 * byte.
	 * 
	 * @return the field's value
	 */
	@Field(offset = 18 * BYTE, length = 16)
	public int urgent() {
		return getUShort(18);
	}

	/**
	 * Urgent.
	 * 
	 * @param urg
	 *            the urg
	 */
	public void urgent(final int urg) {
		super.setUShort(18, urg);
	}

	/**
	 * Window (16 bits). The size of the receive window, which specifies the
	 * number of bytes (beyond the sequence number in the acknowledgment field)
	 * that the receiver is currently willing to receive. <h2>Flow control</h2>
	 * TCP uses an end-to-end flow control protocol to avoid having the sender
	 * send data too fast for the TCP receiver to receive and process it
	 * reliably. Having a mechanism for flow control is essential in an
	 * environment where machines of diverse network speeds communicate. For
	 * example, if a PC sends data to a hand-held PDA that is slowly processing
	 * received data, the PDA must regulate data flow so as not to be
	 * overwhelmed.
	 * <p>
	 * TCP uses a sliding window flow control protocol. In each TCP segment, the
	 * receiver specifies in the receive window field the amount of additional
	 * received data (in bytes) that it is willing to buffer for the connection.
	 * The sending host can send only up to that amount of data before it must
	 * wait for an acknowledgment and window update from the receiving host.
	 * </p>
	 * <p>
	 * When a receiver advertises a window size of 0, the sender stops sending
	 * data and starts the persist timer. The persist timer is used to protect
	 * TCP from a deadlock situation that could arise if the window size update
	 * from the receiver is lost and the sender has no more data to send while
	 * the receiver is waiting for the new window size update. When the persist
	 * timer expires, the TCP sender sends a small packet so that the receiver
	 * sends an acknowledgement with the new window size.
	 * </p>
	 * <p>
	 * If a receiver is processing incoming data in small increments, it may
	 * repeatedly advertise a small receive window. This is referred to as the
	 * silly window syndrome, since it is inefficient to send only a few bytes
	 * of data in a TCP segment, given the relatively large overhead of the TCP
	 * header. TCP senders and receivers typically employ flow control logic to
	 * specifically avoid repeatedly sending small segments. The sender-side
	 * silly window syndrome avoidance logic is referred to as Nagle's
	 * algorithm.
	 * </p>
	 * <h2>Window scaling</h2> For more efficient use of high bandwidth
	 * networks, a larger TCP window size may be used. The TCP window size field
	 * controls the flow of data and its value is limited to between 2 and
	 * 65,535 bytes.
	 * <p>
	 * Since the size field cannot be expanded, a scaling factor is used. The
	 * TCP window scale option, as defined in RFC 1323, is an option used to
	 * increase the maximum window size from 65,535 bytes to 1 Gigabyte. Scaling
	 * up to larger window sizes is a part of what is necessary for TCP Tuning.
	 * </p>
	 * <p>
	 * The window scale option is used only during the TCP 3-way handshake. The
	 * window scale value represents the number of bits to left-shift the 16-bit
	 * window size field. The window scale value can be set from 0 (no shift) to
	 * 14 for each direction independently. Both sides must send the option in
	 * their SYN segments to enable window scaling in either direction.
	 * </p>
	 * <p>
	 * Some routers and packet firewalls rewrite the window scaling factor
	 * during a transmission. This causes sending and receiving sides to assume
	 * different TCP window sizes. The result is non-stable traffic that may be
	 * very slow. The problem is visible on some sending and receiving sites
	 * behind the path of defective routers.
	 * </p>
	 * 
	 * @return the field's value
	 */
	@Field(offset = 14 * BYTE, length = 16)
	public int window() {
		return getUShort(14);
	}

	/**
	 * Sets the window field to new value.
	 * 
	 * @param value
	 *            new value for the field
	 */
	public void window(final int value) {
		super.setUShort(14, value);
	}

	/**
	 * A scaled, window field value. The size of the receive window, which
	 * specifies the number of bytes (beyond the sequence number in the
	 * acknowledgment field) that the receiver is currently willing to receive.
	 * <p>
	 * This getter method, takes into account window scaling, as described
	 * below, and applies the scaling factor and returning the value.
	 * </p>
	 * <h2>Window scaling</h2> For more efficient use of high bandwidth
	 * networks, a larger TCP window size may be used. The TCP window size field
	 * controls the flow of data and its value is limited to between 2 and
	 * 65,535 bytes.
	 * <p>
	 * Since the size field cannot be expanded, a scaling factor is used. The
	 * TCP window scale option, as defined in RFC 1323, is an option used to
	 * increase the maximum window size from 65,535 bytes to 1 Gigabyte. Scaling
	 * up to larger window sizes is a part of what is necessary for TCP Tuning.
	 * </p>
	 * <p>
	 * The window scale option is used only during the TCP 3-way handshake. The
	 * window scale value represents the number of bits to left-shift the 16-bit
	 * window size field. The window scale value can be set from 0 (no shift) to
	 * 14 for each direction independently. Both sides must send the option in
	 * their SYN segments to enable window scaling in either direction.
	 * </p>
	 * <p>
	 * Some routers and packet firewalls rewrite the window scaling factor
	 * during a transmission. This causes sending and receiving sides to assume
	 * different TCP window sizes. The result is non-stable traffic that may be
	 * very slow. The problem is visible on some sending and receiving sites
	 * behind the path of defective routers.
	 * </p>
	 * 
	 * @return the scaled value of the window field
	 */
	public int windowScaled() {
		return window() << 6;
	}
}
