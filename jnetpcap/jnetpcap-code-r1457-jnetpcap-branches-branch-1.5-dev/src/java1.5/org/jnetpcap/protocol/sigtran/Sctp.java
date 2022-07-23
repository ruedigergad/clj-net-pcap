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

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.checksum.Checksum;

/**
 * In computer networking, the Stream Control Transmission Protocol (SCTP) is a
 * transport layer protocol, serving in a similar role to the popular protocols
 * Transmission Control Protocol (TCP) and User Datagram Protocol (UDP). It
 * provides some of the same service features of both: it is message-oriented
 * like UDP and ensures reliable, in-sequence transport of messages with
 * congestion control like TCP.
 * <p>
 * The protocol was defined by the IETF Signaling Transport (SIGTRAN) working
 * group in 2000,[1] and is maintained by the IETF Transport Area (TSVWG)
 * working group. RFC 4960 defines the protocol. RFC 3286 provides an
 * introduction.
 * </p>
 * <p>
 * In the absence of native SCTP support in operating systems it is possible to
 * tunnel SCTP over UDP,[2] as well as mapping TCP API calls to SCTP ones.
 * </p>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 * @see http://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol
 */
@Header(
		length = 12,
		suite = ProtocolSuite.SIGTRAN,
		description = "Stream Control Transmission Protocol")
public class Sctp extends JHeader implements JHeaderChecksum {

	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_ID;

	/**
	 * This is the SCTP sender's port number. It can be used by the receiver in
	 * combination with the source IP address, the SCTP destination port, and
	 * possibly the destination IP address to identify the association to which
	 * this packet belongs. The port number 0 MUST NOT be used.
	 * 
	 * @return source port number
	 * @see RFC4960
	 */
	@Field(format = "%d", offset = 0 * BYTE, length = 2 * BYTE)
	public int source() {
		return super.getUShort(0);
	}

	/**
	 * This is the SCTP sender's port number. It can be used by the receiver in
	 * combination with the source IP address, the SCTP destination port, and
	 * possibly the destination IP address to identify the association to which
	 * this packet belongs. The port number 0 MUST NOT be used.
	 * 
	 * @param port
	 *            source port number
	 * @see RFC4960
	 */
	public void source(int port) {
		super.setUShort(0, port);
	}

	/**
	 * Field description
	 * 
	 * @return description
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String sourceDescription() {
		switch (source()) {
		case 80:
		case 8080:
		case 8081:
			return "HTTP";

		case 3868:
			return "DIAMETER";
		}

		return null;
	}

	/**
	 * Field description
	 * 
	 * @return description
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String destinationDescription() {
		switch (destination()) {
		case 80:
		case 8080:
		case 8081:
			return "HTTP";

		case 3868:
			return "DIAMETER";
		}

		return null;
	}

	/**
	 * This is the SCTP port number to which this packet is destined. The
	 * receiving host will use this port number to de-multiplex the SCTP packet
	 * to the correct receiving endpoint/application. The port number 0 MUST NOT
	 * be used.
	 * 
	 * @return destination port number
	 * @see RFC4960
	 */
	@Field(format = "%d", offset = 2 * BYTE, length = 2 * BYTE)
	public int destination() {
		return super.getUShort(2);
	}

	/**
	 * This is the SCTP port number to which this packet is destined. The
	 * receiving host will use this port number to de-multiplex the SCTP packet
	 * to the correct receiving endpoint/application. The port number 0 MUST NOT
	 * be used.
	 * 
	 * @param port
	 *            destination port number
	 * @see RFC4960
	 */
	public void destination(int port) {
		super.setUShort(2, port);
	}

	/**
	 * The receiver of this packet uses the Verification Tag to validate the
	 * sender of this SCTP packet. On transmit, the value of this Verification
	 * Tag MUST be set to the value of the Initiate Tag received from the peer
	 * endpoint during the association initialization, with the following
	 * exceptions:
	 * <ul>
	 * <li>A packet containing an INIT chunk MUST have a zero Verification Tag.
	 * 
	 * <li>A packet containing a SHUTDOWN COMPLETE chunk with the T bit set MUST
	 * have the Verification Tag copied from the packet with the SHUTDOWN ACK
	 * chunk.
	 * 
	 * <li>A packet containing an ABORT chunk may have the verification tag
	 * copied from the packet that caused the ABORT to be sent. For details see
	 * RFC 4960 Section 8.4 and Section 8.5.
	 * </ul>
	 * 
	 * @return verification tag
	 * @see RFC4960
	 */
	@Field(format = "%x", offset = 4 * BYTE, length = 4 * BYTE)
	public long tag() {
		return super.getUInt(4);
	}

	/**
	 * The receiver of this packet uses the Verification Tag to validate the
	 * sender of this SCTP packet. On transmit, the value of this Verification
	 * Tag MUST be set to the value of the Initiate Tag received from the peer
	 * endpoint during the association initialization, with the following
	 * exceptions:
	 * <ul>
	 * <li>A packet containing an INIT chunk MUST have a zero Verification Tag.
	 * 
	 * <li>A packet containing a SHUTDOWN COMPLETE chunk with the T bit set MUST
	 * have the Verification Tag copied from the packet with the SHUTDOWN ACK
	 * chunk.
	 * 
	 * <li>A packet containing an ABORT chunk may have the verification tag
	 * copied from the packet that caused the ABORT to be sent. For details see
	 * RFC 4960 Section 8.4 and Section 8.5.
	 * </ul>
	 * 
	 * @param tag
	 *            verification tag
	 */
	public void tag(long tag) {
		super.setUInt(4, tag);
	}

	/**
	 * This field contains the checksum of this SCTP packet. Its calculation is
	 * discussed in RFC 4960 Section 6.8. SCTP uses the CRC32c algorithm as
	 * described in RFC 4960 Appendix B for calculating the checksum.
	 * 
	 * @return value of the checksum field
	 * @see RFC4960 TODO: Work around the formatter bug where unsigned
	 */
	@Field(
			offset = 8 * BYTE,
			length = 4 * BYTE,
			format = "%x",
			name = "checksum")
	public int checksum() {
		return super.getInt(8);
	}

	/**
	 * Checksum description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {
		final long crc32 = calculateChecksum();
		if (checksum() == crc32) {
			return "correct";
		} else {
			return "incorrect: 0x" + Long.toHexString(crc32).toUpperCase();
		}
	}

	/**
	 * Calculate checksum.
	 * 
	 * @return the long
	 */
	public int calculateChecksum() {
		final JPacket packet = getPacket();
		int save = checksum();
		checksum(0); // Reset to 0, a requirement for calculation
		int crc =
				Checksum.sctp(packet, getOffset(), getHeaderLength()
						+ getPayloadLength());
		// int crc = Checksum.crc32IEEE802(packet, 0, getHeaderLength()
		// + getPayloadLength());

		checksum(save); // Restore CRC

		return crc;
	}

	/**
	 * This field contains the checksum of this SCTP packet. Its calculation is
	 * discussed in RFC 4960 Section 6.8. SCTP uses the CRC32c algorithm as
	 * described in Appendix B for calculating the checksum.
	 * 
	 * @param crc
	 *            value of the checksum field
	 * @see RFC4960
	 */
	public boolean checksum(int crc) {
		super.setUInt(8, crc);

		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeaderChecksum#isChecksumValid()
	 */
	@Override
	public boolean isChecksumValid() {
		return checksum() == calculateChecksum();

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeaderChecksum#recalculateChecksum()
	 */
	@Override
	public boolean recalculateChecksum() {
		return checksum(calculateChecksum());
	}

}
