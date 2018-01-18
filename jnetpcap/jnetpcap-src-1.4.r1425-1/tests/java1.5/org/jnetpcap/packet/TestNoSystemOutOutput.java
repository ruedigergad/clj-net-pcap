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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintStream;

import org.jnetpcap.packet.format.TextFormatter;

import junit.framework.TestCase;

// TODO: Auto-generated Javadoc
/**
 * Perform various tasks that should not generate output to either System.out or
 * System.err. Redirect those to a StringBuilder (Appendable) and check for 0
 * output in the buffer. This ensure that nothing (debug messages especially)
 * has been generated inadvertantly.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestNoSystemOutOutput
    extends
    TestCase {

	/** The Constant DIR. */
	private final static File DIR = new File("tests");

	/** The saved out. */
	private PrintStream savedOut;

	/** The saved err. */
	private PrintStream savedErr;

	/** The out. */
	private ByteArrayOutputStream out;

	/** The DISGAR d_ output. */
	private TextFormatter DISGARD_OUTPUT = new TextFormatter(TestUtils.DEV_NULL);

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		savedOut = System.out;
		savedErr = System.err;

		out = new ByteArrayOutputStream();
		System.setOut(new PrintStream(out));
		System.setErr(new PrintStream(out));
	}

	/**
	 * Reset.
	 */
	private void reset() {
		out = new ByteArrayOutputStream();
		System.setOut(new PrintStream(out));
		System.setErr(new PrintStream(out));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		System.setOut(savedOut);
		System.setErr(savedErr);
	}

	/**
	 * Test system out redirection is working.
	 */
	public void testSystemOutRedirectionIsWorking() {
		assertTrue("redirection failed", out.size() == 0);

		System.err.println("hello");
		assertFalse("redirection failed", out.size() == 0);
		reset();
	}

	/**
	 * Test no output from core protocols.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testNoOutputFromCoreProtocols() throws IOException {

		String[] files = DIR.list(new FilenameFilter() {

			public boolean accept(File dir, String name) {
				return name.endsWith(".pcap");
			}

		});

//		int count = 0;
		for (String f : files) {
			for (PcapPacket packet : TestUtils.getIterable(DIR + "/" + f)) {
//				savedOut.printf("TestNoSystemOutput() #%d\n", count ++);
//				savedOut.flush();
//				
				
				DISGARD_OUTPUT.format(packet);
				assertTrue("unexpected System.out output found " + f + ": packet="
				    + packet.toString() + "\noutput found=" + out.toString(), out.size() == 0);
			}
		}
	}

}
