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
package org.jnetpcap.bugs;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.TestUtils;

/**
 * The Class Bug2827356_PcapPacketHandler_Fails.
 */
public class Bug2827356_PcapPacketHandler_Fails
    extends
    TestUtils {

	/** The Constant SMALL_ICMP_FILE. */
	public final static String SMALL_ICMP_FILE = "tests/test-small-imap.pcap";

	/** The pcap. */
	private Pcap pcap;

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		pcap = TestUtils.openOffline(SMALL_ICMP_FILE);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		pcap.close();
		pcap = null;
	}

	/**
	 * Test validate http j buffer packet handler.
	 */
  public void testValidateHttpJBufferPacketHandler() {
  
  	pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {
  
  		public void nextPacket(PcapHeader header, JBuffer buffer, Pcap user) {
  			assertNotNull(buffer);
  		}
  
  	}, pcap);
  }

	/**
	 * Test validate http pcap packet handler.
	 */
	public void testValidateHttpPcapPacketHandler() {

		pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<Pcap>() {

			public void nextPacket(PcapPacket packet, Pcap user) {
				assertNotNull(packet);

				System.out.println(packet);
			}

		}, pcap);
	}

	/**
	 * Test validate http j buffer packet handler with local packet scanner.
	 */
	public void testValidateHttpJBufferPacketHandlerWithLocalPacketScanner() {

		pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {

			public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {
				assertNotNull(buffer);

				final int id = JRegistry.mapDLTToId(pcap.datalink());

				PcapPacket packet = new PcapPacket(header, buffer);
				assertNotNull(packet);

				packet.scan(id);
			}

		}, pcap);
	}

	/**
	 * Test validate http j buffer packet handler with global scanner.
	 */
	public void testValidateHttpJBufferPacketHandlerWithGlobalScanner() {

		pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {

			public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {
				assertNotNull(buffer);

				final int id = JRegistry.mapDLTToId(pcap.datalink());

				PcapPacket packet = new PcapPacket(header, buffer);
				assertNotNull(packet);

				JScanner scanner = JScanner.getThreadLocal();
				scanner.scan(packet, id);
			}

		}, pcap);
	}

}
