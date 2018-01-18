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

import junit.framework.TestCase;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.application.Html;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestHtml
    extends
    TestCase {

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
	 * Test http formatting with resolve address disabled.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testHttpFormattingWithResolveAddressDisabled() throws IOException {

		PcapPacket packet = TestUtils.getPcapPacket("tests/test-http-jpeg.pcap", 5);

		assertTrue("Can't find HTTP header", packet.hasHeader(JProtocol.HTTP_ID));

		Html html = packet.getHeader(new Html());
		assertNotNull("Can't find HTML header", html);
		System.out.printf("link related tags=%s\n", Arrays.asList(html.links())
		    .toString());

		System.out.printf("All tags=%s\n", Arrays.asList(html.tags()).toString());

	}
}
