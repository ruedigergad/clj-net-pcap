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

import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * Initiation SCTP Chunk(INIT) (1)
 * <p>
 * This chunk is used to initiate an SCTP association between two endpoints. The
 * format of the INIT chunk is shown below:
 * </p>
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 1    |  Chunk Flags  |      Chunk Length             |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                         Initiate Tag                          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |           Advertised Receiver Window Credit (a_rwnd)          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |  Number of Outbound Streams   |  Number of Inbound Streams    |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                          Initial TSN                          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        \                                                               \
 *        /              Optional/Variable-Length Parameters              /
 *        \                                                               \
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * The INIT chunk contains the following parameters. Unless otherwise noted,
 * each parameter MUST only be included once in the INIT chunk.
 * 
 * <pre>
 *             Fixed Parameters                     Status
 *             ----------------------------------------------
 *             Initiate Tag                        Mandatory
 *             Advertised Receiver Window Credit   Mandatory
 *             Number of Outbound Streams          Mandatory
 *             Number of Inbound Streams           Mandatory
 *             Initial TSN                         Mandatory
 * 
 *           Variable Parameters                  Status     Type Value
 *           -------------------------------------------------------------
 *           IPv4 Address (Note 1)               Optional    5 IPv6 Address
 *           (Note 1)               Optional    6 Cookie Preservative
 *           Optional    9 Reserved for ECN Capable (Note 2)   Optional
 *           32768 (0x8000) Host Name Address (Note 3)          Optional
 *           11 Supported Address Types (Note 4)    Optional    12
 * </pre>
 * <p>
 * Note 1: The INIT chunks can contain multiple addresses that can be IPv4
 * and/or IPv6 in any combination.
 * </p>
 * <p>
 * Note 2: The ECN Capable field is reserved for future use of Explicit
 * Congestion Notification.
 * </p>
 * <p>
 * Note 3: An INIT chunk MUST NOT contain more than one Host Name Address
 * parameter. Moreover, the sender of the INIT MUST NOT combine any other
 * address types with the Host Name Address in the INIT. The receiver of INIT
 * MUST ignore any other address types if the Host Name Address parameter is
 * present in the received INIT chunk.
 * </p>
 * <p>
 * Note 4: This parameter, when present, specifies all the address types the
 * sending endpoint can support. The absence of this parameter indicates that
 * the sending endpoint can support any address type.
 * 
 * IMPLEMENTATION NOTE: If an INIT chunk is received with known parameters that
 * are not optional parameters of the INIT chunk, then the receiver SHOULD
 * process the INIT chunk and send back an INIT ACK. The receiver of the INIT
 * chunk MAY bundle an ERROR chunk with the COOKIE ACK chunk later. However,
 * restrictive implementations MAY send back an ABORT chunk in response to the
 * INIT chunk.
 * 
 * The Chunk Flags field in INIT is reserved, and all bits in it should be set
 * to 0 by the sender and ignored by the receiver. The sequence of parameters
 * within an INIT can be processed in any order.
 * </p>
 * <h4>Initiate Tag: 32 bits (unsigned integer)</h4>
 * 
 * The receiver of the INIT (the responding end) records the value of the
 * Initiate Tag parameter. This value MUST be placed into the Verification Tag
 * field of every SCTP packet that the receiver of the INIT transmits within
 * this association. </p>
 * <p>
 * The Initiate Tag is allowed to have any value except 0. See RFC 4960 Section 5.3.1 for
 * more on the selection of the tag value.
 * </p>
 * <p>
 * If the value of the Initiate Tag in a received INIT chunk is found to be 0,
 * the receiver MUST treat it as an error and close the association by
 * transmitting an ABORT.
 * </p>
 * <h4>Advertised Receiver Window Credit (a_rwnd): 32 bits (unsigned integer)</h4>
 * 
 * This value represents the dedicated buffer space, in number of bytes, the
 * sender of the INIT has reserved in association with this window. During the
 * life of the association, this buffer space SHOULD NOT be lessened (i.e.,
 * dedicated buffers taken away from this association); however, an endpoint MAY
 * change the value of a_rwnd it sends in SACK chunks.
 * 
 * <h4>Number of Outbound Streams (OS): 16 bits (unsigned integer)</h4>
 * 
 * Defines the number of outbound streams the sender of this INIT chunk wishes
 * to create in this association. The value of 0 MUST NOT be used. </p>
 * <p>
 * Note: A receiver of an INIT with the OS value set to 0 SHOULD abort the
 * association.
 * </p>
 * <h4>Number of Inbound Streams (MIS): 16 bits (unsigned integer)</h4>
 * 
 * Defines the maximum number of streams the sender of this INIT chunk allows
 * the peer end to create in this association. The value 0 MUST NOT be used.
 * </p>
 * <p>
 * Note: There is no negotiation of the actual number of streams but instead the
 * two endpoints will use the min(requested, offered). See RFC 4960 Section 5.1.1 for
 * details.
 * </p>
 * <p>
 * Note: A receiver of an INIT with the MIS value of 0 SHOULD abort the
 * association.
 * </p>
 * <h4>Initial TSN (I-TSN): 32 bits (unsigned integer)</h4>
 * 
 * Defines the initial TSN that the sender will use. The valid range is from 0
 * to 4294967295. This field MAY be set to the value of the Initiate Tag field.
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Initiation ", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-init")
public class SctpInit extends SctpInitBaseclass {

	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_INIT_ID;

}
