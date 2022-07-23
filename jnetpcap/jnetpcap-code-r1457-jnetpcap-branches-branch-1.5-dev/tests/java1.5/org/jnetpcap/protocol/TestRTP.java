/**
 * 
 */
package org.jnetpcap.protocol;

import java.io.PrintStream;

import junit.framework.TestCase;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.RtcpApp;
import org.jnetpcap.protocol.voip.RtcpBye;
import org.jnetpcap.protocol.voip.RtcpReceiverReport;
import org.jnetpcap.protocol.voip.RtcpSDES;
import org.jnetpcap.protocol.voip.RtcpSenderReport;
import org.jnetpcap.protocol.voip.Rtp;
import org.junit.Test;

/**
 * Test RTP and RTCP protocol basics
 * 
 * @author Sly Technologies Inc.
 */
public class TestRTP extends TestCase {
	// private final PrintStream out = TestUtils.DISCARD;
	private final PrintStream out = System.out;

	private final static String FILE = "tests/test-sip-rtp.pcap";

	@Test
	public void testRTP() {

		boolean foundRtp = false;
		for (JPacket packet : TestUtils.getIterable(FILE)) {
			if (packet.hasHeader(Rtp.ID)) {
				foundRtp = true;
				out.println(packet.getState().toDebugString());
				out.printf("#%d - RTP%n", packet.getFrameNumber());
			}
		}

		TestCase.assertTrue("RTP not found", foundRtp);
	}

	@Test
	public void testRTCP() {

		long mask = JProtocol.createMaskFromIds(RtcpSenderReport.ID,
				RtcpReceiverReport.ID, RtcpSDES.ID, RtcpApp.ID, RtcpBye.ID);

		boolean foundRtcp = false;
		JPacket.getDefaultScanner().setFrameNumber(1);
		for (JPacket packet : TestUtils.getIterable(FILE)) {
			int group = JProtocol.maskToGroup(mask);
			out.printf("group=%d mask=0x%016X map=%016X%n", group, mask, packet
					.getState().get64BitHeaderMap(group));

			if (packet.hasHeader(Udp.ID)) {
				out.println(packet.getHeader(new Udp()));
			}
			out.println(packet.getState().toDebugString());
			if (packet.hasAnyHeader(mask)) {
				foundRtcp = true;
				out.println(packet);
				out.printf("#%d - RTCP%n", packet.getFrameNumber());

				break;
			}
			
			if (packet.getFrameNumber() == 634) {
				break;
			}
		}

		TestCase.assertTrue("RTCP not found", foundRtcp);
	}
	public void testProtocolBitmaskCombine() {
		long mask = JProtocol.createMaskFromIds(RtcpSenderReport.ID,
				RtcpReceiverReport.ID, RtcpSDES.ID, RtcpApp.ID, RtcpBye.ID);
		long mask2 = JProtocol.createMaskFromProtocols(
				JProtocol.RTCP_SENDER_REPORT, JProtocol.RTCP_RECEIVER_REPORT,
				JProtocol.RTCP_BYE, JProtocol.RTCP_SDES, JProtocol.RTCP_APP);
		TestCase.assertEquals(mask, mask2);
	}
}
