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
package org.jnetpcap.protocol;

import java.io.IOException;
import java.io.PrintStream;

import junit.framework.TestCase;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.sigtran.Sctp;
import org.junit.Test;

/**
 * @author Sly Technologies, Inc.
 * 
 */
public class TestSctp extends TestCase {

	PrintStream out = TestUtils.DISCARD;

	private final static String FILE = "tests/test-sctp-www.pcap";
	// private final static String FILE = "tests/diaS6a2K5tps10KTot2.pcap";

	public void testSctpHeader() throws IOException {
		Sctp sctp = new Sctp();

		// out.println(JRegistry.toDebugString());

		JPacket.getDefaultScanner().setFrameNumber(1);

		int i = 1;
		for (JPacket packet : TestUtils.getIterable(FILE)) {
			// out.println(packet.getState().toDebugString());
			out.println(packet);

			TestCase.assertTrue("", packet.hasHeader(Sctp.ID));
			TestCase.assertTrue("", packet.hasHeader(sctp));
			if (i++ == 76) {
				out.println(packet.getState().toDebugString());
			}
		}
	}

	@Test
	public void testPacketFilterByType() {

		JPacket.getDefaultScanner().setFrameNumber(1);

		for (JPacket packet : TestUtils.getIterable(FILE)) {

			for (JHeaderChecksum sum : packet
					.filterByType(JHeaderChecksum.class)) {
				JHeader header = (JHeader) sum;
				assertNotNull(header);
				out.printf("#%d %10s sum=%08X%n", header.getPacket()
						.getFrameNumber(), header.getName(), sum.checksum());
			}
		}
	}

}
