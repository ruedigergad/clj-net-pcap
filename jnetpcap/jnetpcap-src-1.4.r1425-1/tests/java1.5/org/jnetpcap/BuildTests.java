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
package org.jnetpcap;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.jnetpcap.format.TestFormatter;
import org.jnetpcap.header.TestHttp;
import org.jnetpcap.header.TestIcmp;
import org.jnetpcap.header.TestIpv6;
import org.jnetpcap.header.TestSubHeader;
import org.jnetpcap.nio.TestJBuffer;
import org.jnetpcap.nio.TestJMemory;
import org.jnetpcap.packet.JHandlerTest;
import org.jnetpcap.packet.TestHeaderState;
import org.jnetpcap.packet.TestJHeader;
import org.jnetpcap.packet.TestJRegistry;
import org.jnetpcap.packet.TestJScanner;
import org.jnetpcap.packet.TestNoSystemOutOutput;
import org.jnetpcap.packet.TestPcapPacket;
import org.jnetpcap.packet.TestPcapUtils;
import org.jnetpcap.protocol.TestNetwork;
import org.jnetpcap.protocol.TestRTP;
import org.jnetpcap.protocol.TestSctp;
import org.jnetpcap.protocol.TestSip;
import org.jnetpcap.protocol.TestTcpIp;
import org.jnetpcap.protocol.TestVoip;
import org.jnetpcap.util.TestExpandableString;
import org.jnetpcap.util.TestSearchPaths;

// TODO: Auto-generated Javadoc
/**
 * The Class BuildTests.
 */
public class BuildTests {

	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {

		TestSuite suite = new TestSuite("Test for org.jnetpcap");

		for (int i = 0; i < 1; i++) {
			// $JUnit-BEGIN$
			suite.addTestSuite(TestPcapUtils.class);
			suite.addTestSuite(TestPcapPacket.class);
			suite.addTestSuite(TestPcapDumper.class);
			suite.addTestSuite(JHandlerTest.class);
			suite.addTestSuite(TestJRegistry.class);
			suite.addTestSuite(TestJScanner.class);
			suite.addTestSuite(TestPcapUtils.class);
			suite.addTestSuite(TestSubHeader.class);
			suite.addTestSuite(TestIcmp.class);
			suite.addTestSuite(TestJBuffer.class);
			suite.addTestSuite(TestJMemory.class);
			suite.addTestSuite(TestFormatter.class);
			/*
			 * suite.addTestSuite(TestPcapDispatchers.class);
			 */
			suite.addTestSuite(TestHttp.class);
			suite.addTestSuite(TestIpv6.class);
			suite.addTestSuite(TestExpandableString.class);
			suite.addTestSuite(TestSearchPaths.class);
			suite.addTestSuite(TestJHeader.class);
			suite.addTestSuite(TestVoip.class);
			suite.addTestSuite(TestSctp.class);
			suite.addTestSuite(TestTcpIp.class);
			suite.addTestSuite(TestNetwork.class);
			suite.addTestSuite(TestHeaderState.class);
			suite.addTestSuite(TestRTP.class);
			suite.addTestSuite(TestSip.class);
			suite.addTestSuite(TestNoSystemOutOutput.class);
		}

		// $JUnit-END$
		return suite;
	}

}
