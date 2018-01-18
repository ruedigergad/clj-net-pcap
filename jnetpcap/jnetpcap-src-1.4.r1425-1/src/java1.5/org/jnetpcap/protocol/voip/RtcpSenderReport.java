/**
 * 
 */
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * SR: Sender Report RTCP Packet
 * <p>
 * The sender report packet consists of three sections, possibly followed by a
 * fourth profile-specific extension section if defined. The first section, the
 * header, is 8 octets long.
 * </p>
 * 
 * @author Sly Technologies Inc.
 * @since 1.4
 */
@Header(length = 4, name = "RTCP-SR", suite = ProtocolSuite.TCP_IP)
public class RtcpSenderReport extends RtcpSSRC {

	/**
	 * SR: Sender Report RTCP Packet
	 */
	public final static int ID = JProtocol.RTCP_SENDER_REPORT_ID;

	/**
	 * record count (RC): 5 bits
	 * <p>
	 * The number of reception report blocks contained in this packet. A value
	 * of zero is valid.
	 * </p>
	 * 
	 * @return number of report blocks
	 */
	@Field(offset = 3, length = 5, display = "report count")
	public int rc() {
		return (super.getByte(0) & 0x1F) >> 0;
	}

}
