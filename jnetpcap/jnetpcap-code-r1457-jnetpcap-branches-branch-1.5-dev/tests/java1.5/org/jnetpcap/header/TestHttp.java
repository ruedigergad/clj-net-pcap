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
package org.jnetpcap.header;

import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;

import junit.framework.TestCase;

import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.util.JLogger;
import org.jnetpcap.util.config.JConfig;
import org.jnetpcap.util.resolver.Resolver;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class TestHttp
    extends
    TestCase {

	// private final static Appendable OUT = TestUtils.DEV_NULL;
	/** The Constant OUT. */
	private final static Appendable OUT = System.out;

	/** The http. */
	private Http http = new Http();

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	/**
	 * Test registration.
	 */
	public void testRegistration() {
		assertTrue(JRegistry.lookupId(Http.class) > 12);
	}

	/**
	 * Test http formatting with resolve address disabled.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testHttpFormattingWithResolveAddressDisabled() throws IOException {
		JFormatter out = new TextFormatter(OUT);
		out.setResolveAddresses(false);

		PcapPacket packet = TestUtils.getPcapPacket("tests/test-http-jpeg.pcap", 5);

		Ip4 ip = new Ip4();
		Ethernet eth = new Ethernet();
		if (packet.hasHeader(eth)) {
			out.format(eth);
		}
		if (packet.hasHeader(ip)) {
			out.format(ip);
			out.format(ip);
		}

		out.format(packet);

		Html html = new Html();
		assertTrue("html header not found", packet.hasHeader(html));
		System.out.printf("link related tags=%s\n", Arrays.asList(html.links())
		    .toString());

		// if (true && packet.hasHeader(http)) {
		//
		// for (String e : http.fieldArray()) {
		// System.out.println(e);
		// }
		// }
	}

	/**
	 * Test http formatting with resolve address enabled.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testHttpFormattingWithResolveAddressEnabled() throws IOException {
		JLogger.getLogger(JConfig.class).setLevel(Level.FINE);

		JLogger.getLogger(Resolver.class.getPackage()).setLevel(Level.FINER);

		JFormatter out = new TextFormatter(OUT);
		out.setResolveAddresses(true);

		PcapPacket packet = TestUtils.getPcapPacket("tests/test-http-jpeg.pcap", 5);

		Ip4 ip = new Ip4();
		Ethernet eth = new Ethernet();
		if (packet.hasHeader(eth)) {
			out.format(eth);
		}
		if (packet.hasHeader(ip)) {
			// out.format(ip);
			out.format(ip);
			System.out.println();
		}

		// out.format(packet);

		// if (true && packet.hasHeader(http)) {
		// Map<String, Http.Entry> map = http.headerFields();
		//
		// for (Entry e : map.values()) {
		// System.out.println(e.toString());
		// }
		// }

		JRegistry.shutdown();
	}
}
