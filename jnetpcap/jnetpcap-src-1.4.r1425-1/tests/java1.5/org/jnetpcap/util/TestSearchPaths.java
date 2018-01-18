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
package org.jnetpcap.util;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import junit.framework.TestCase;

import org.jnetpcap.util.config.JConfig;
import org.jnetpcap.util.config.JConfig.SearchPath;
import org.jnetpcap.util.resolver.Resolver;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestSearchPaths
    extends TestCase {

	/** The logger. */
	private static Logger logger = JLogger.getLogger(JConfig.class);

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
	 * _test cache search path.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void _testCacheSearchPath() throws IOException {
		logger.setLevel(Level.FINER);

		assertNotNull("failed to locate IP resolver file", JConfig.getInputStream(
		    "IP", Resolver.RESOLVER_SEARCH_PATH_PROPERTY));

	}

	/**
	 * _test resource search path oui txt file.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void _testResourceSearchPathOuiTxtFile() throws IOException {
		logger.setLevel(Level.FINER);

		assertNotNull("failed to locate oui.txt resource file", JConfig
		    .getResourceInputStream("oui.txt"));
	}

	/**
	 * _test resource search path oui txt url.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void _testResourceSearchPathOuiTxtURL() throws IOException {
		logger.setLevel(Level.FINER);

		URL url = null;
		assertNotNull("failed to locate oui.txt resource file", url =
		    JConfig.getResourceURL("oui.txt"));

		System.out.println(url);

	}

	/**
	 * Test search path from property.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testSearchPathFromProperty() throws IOException {
		logger.setLevel(Level.FINER);

		for (SearchPath p : JConfig
		    .createSearchPath(Resolver.RESOLVER_SEARCH_PATH_PROPERTY)) {

			System.out.println(p.toString());
		}
	}

}
