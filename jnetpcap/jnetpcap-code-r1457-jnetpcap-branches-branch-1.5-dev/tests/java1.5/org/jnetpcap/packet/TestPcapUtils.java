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
package org.jnetpcap.packet;

import junit.framework.TestCase;

import org.jnetpcap.packet.format.FormatUtils;


// TODO: Auto-generated Javadoc
/**
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class TestPcapUtils
    extends TestCase {

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
	 * Test ip6 address conversion.
	 */
	public void testIp6AddressConversion() {

		byte[] a = new byte[] {
		    1,
		    2,
		    3,
		    4,
		    5,
		    6,
		    7,
		    8,
		    9,
		    10,
		    11,
		    12,
		    13,
		    14,
		    15,
		    16

		};
		
		System.out.println(FormatUtils.asStringIp6(a, true));

	}
	
	/**
	 * Test ip6 with middle hole.
	 */
	public void testIp6WithMiddleHole() {

		byte[] a = new byte[] {
		    1,
		    2,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    11,
		    12,
		    13,
		    14,
		    15,
		    16

		};
		
		System.out.println(FormatUtils.asStringIp6(a, false));
		System.out.println(FormatUtils.asStringIp6(a, true));

	}

	/**
	 * Test ip6 with front hole.
	 */
	public void testIp6WithFrontHole() {

		byte[] a = new byte[] {
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    9,
		    10,
		    11,
		    12,
		    13,
		    14,
		    15,
		    16

		};
		
		System.out.println(FormatUtils.asStringIp6(a, false));
		System.out.println(FormatUtils.asStringIp6(a, true));

	}
	
	/**
	 * Test ip6 with back hole.
	 */
	public void testIp6WithBackHole() {

		byte[] a = new byte[] {
		    9,
		    10,
		    11,
		    12,
		    13,
		    14,
		    15,
		    16,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,

		};
		
		System.out.println(FormatUtils.asStringIp6(a, false));
		System.out.println(FormatUtils.asStringIp6(a, true));

	}

	/**
	 * Test ip6 with odd hole.
	 */
	public void testIp6WithOddHole() {

		byte[] a = new byte[] {
		    9,
		    10,
		    11,
		    12,
		    13,
		    14,
		    15,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,

		};
		
		System.out.println(FormatUtils.asStringIp6(a, false));
		System.out.println(FormatUtils.asStringIp6(a, true));

	}


}
