/**
 * 
 */
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * RR: Receiver Report RTCP Packet
 * 
 * 
 * <p>
 * The format of the receiver report (RR) packet is the same as that of the SR
 * packet except that the packet type field contains the constant 201 and the
 * five words of sender information are omitted (these are the NTP and RTP
 * timestamps and sender's packet and octet counts). The remaining fields have
 * the same meaning as for the SR packet.
 * </p>
 * <p>
 * An empty RR packet (RC = 0) MUST be put at the head of a compound RTCP packet
 * when there is no data transmission or reception to report.
 * </p>
 * 
 * @author Sly Technologies Inc.
 * @since 1.4
 */
@Header(length = 4, name = "RTCP-RR", suite = ProtocolSuite.TCP_IP)
public class RtcpReceiverReport extends RtcpSSRC {

	/**
	 * RR: Receiver Report RTCP Packet
	 */
	public final static int ID = JProtocol.RTCP_RECEIVER_REPORT_ID;
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
