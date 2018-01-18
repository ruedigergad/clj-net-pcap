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
package org.jnetpcap.format;

import java.io.IOException;

import junit.framework.TestCase;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.format.XmlFormatter;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestFormatter
    extends TestCase {
	
//private final static Appendable OUT = TestUtils.DEV_NULL;
	/** The Constant OUT. */
private final static Appendable OUT = System.out;

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
	 * Test text formatter.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testTextFormatter() throws IOException {
		JFormatter out = new TextFormatter(OUT);
		
		JPacket packet = TestUtils.getPcapPacket("tests/test-vlan.pcap", 0);
		try {
			out.format(packet);
	    
    } catch (Exception e) {
    	e.printStackTrace();
    }
	}

	/**
	 * Test xml formatter.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testXmlFormatter() throws IOException {
		JFormatter out = new XmlFormatter(OUT);
		
		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		out.format(packet);
	}
	
	/**
	 * Test xml ip4 record route opt.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testXmlIp4RecordRouteOpt() throws IOException {
		JFormatter out = new XmlFormatter(OUT);
		
		JPacket packet = TestUtils.getPcapPacket("tests/test-icmp-recordroute-opt.pcap", 0);

		out.format(packet);
	}

	
	/**
	 * Test sub header.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testSubHeader() throws IOException {
		JFormatter out = new TextFormatter(OUT);
		
		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		out.format(packet);
	}

}
