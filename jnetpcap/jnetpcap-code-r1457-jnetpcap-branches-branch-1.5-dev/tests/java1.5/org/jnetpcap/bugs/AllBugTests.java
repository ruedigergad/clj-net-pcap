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

import junit.framework.Test;
import junit.framework.TestSuite;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AllBugTests {

	/**
	 * Run all the bugs
	 * 
	 * @return the test
	 */
	public static Test suite() {

		TestSuite suite = new TestSuite("Test for org.jnetpcap.bugs");
		// $JUnit-BEGIN$
		suite.addTestSuite(Bug2827356_PcapPacketHandler_Fails.class);
		suite.addTestSuite(Bug2818101_RtpHeaderLength_Invalid.class);
		suite.addTestSuite(Bug2828030_wirelen_not_set_in_JMemoryPacket.class);
		suite.addTestSuite(Bug2832692_null_ptr_in_hasHeader.class);
		suite.addTestSuite(Bug2847124_jbytebuffer_handler_memory_leak.class);
		suite.addTestSuite(Bug2878768_jmemory_packet_int.class);
		suite.addTestSuite(Bug2836179_negative_snaplen.class);
		// $JUnit-END$
		return suite;
	}
}
