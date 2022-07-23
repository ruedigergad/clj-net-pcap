/**
 * 
 */
package org.jnetpcap.protocol;

import junit.framework.TestCase;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.lan.NullHeader;
import org.junit.Test;

/**
 * Tests for NullHeader compliance verification
 * 
 * @author Sly Technologies Inc.
 */
public class TestNullHeader {

	/**
	 * PCAP file generated using <em>rtpproxy</em> tool.
	 * 
	 * @see http://www.rtpproxy.org
	 */
	private final static String FILE = "tests/DLT_NULL.rtp.cap";

	/**
	 * Test proper NullHeader presence. NullHeader is a header with ID > 32,
	 * which needs to be verified that is properly bit encoded in bit-mask.
	 */
	@Test
	public void testNullHeader() {

		NullHeader nh = new NullHeader();

		for (JPacket packet : TestUtils.getIterable(FILE)) {
			TestCase.assertTrue("NullHeader by ID missing",
					packet.hasHeader(JProtocol.NULL_HEADER_ID));
			TestCase.assertTrue("NullHeader by object missing",
					packet.hasHeader(nh));
			
			System.out.println(packet);
			System.out.println(packet.getState().toDebugString());
		}
	}

}
