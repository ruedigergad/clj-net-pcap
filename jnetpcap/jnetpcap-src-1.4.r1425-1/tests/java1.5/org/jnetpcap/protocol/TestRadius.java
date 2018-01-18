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
import java.io.InputStream;

import junit.framework.TestCase;

import org.jnetpcap.protocol.tcpip.radius.FreeRadiusTokenizer;
import org.jnetpcap.protocol.tcpip.radius.FreeRadiusTokenizer.Token;
import org.jnetpcap.protocol.tcpip.radius.FreeRadiusTokenizer.TokenType;
import org.jnetpcap.protocol.tcpip.radius.FreeRadiusDictionary;

/**
 * @author Sly Technologies, Inc.
 * 
 */
public class TestRadius extends TestCase {

	public void _testTokenizer() {

		String resource = "org/jnetpcap/protocol/tcpip/radius/dictionary.usr";

		InputStream in =
				TestRadius.class.getClassLoader().getResourceAsStream(resource);
		assertNotNull(resource, in);

		FreeRadiusTokenizer tokens = new FreeRadiusTokenizer(in);

		for (Token token : tokens) {
			System.out.printf("%s ", token.toString());

			if (token.type == TokenType.EOL) {
				System.out.println();
				continue;
			}
		}
	}

	public void testParser() throws IOException {

		FreeRadiusDictionary parser = new FreeRadiusDictionary();

		parser.process();
		// parser.process("dictionary.starent");
		// parser.process("dictionary.apc");
		// parser.process("dictionary.usr");
		// parser.process("dictionary.walabi");

	}

}
