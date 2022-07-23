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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import junit.framework.TestCase;

import org.jnetpcap.util.config.ConfigString;
import org.jnetpcap.util.config.JConfig;

// TODO: Auto-generated Javadoc
/**
 * A special StringBuilder like class that replaces instances of property names
 * and variable names with their values after doing a lookup.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestExpandableString
    extends TestCase {

	/**
	 * Constant that makes result comparison easier and less error prone
	 */
	private final static String COMPANY = "ACNE, Inc.";

	/**
	 * Constant that makes result comparison easier and less error prone
	 */
	private final static String JNP = "org.jnetpcap";

	/**
	 * Constant that makes result comparison easier and less error prone
	 */
	private final static String SUFFIX = ".ext";

	/** The variables. */
	private static Map<String, String> variables;

	/** The properties. */
	private static Properties properties;

	/** The logger. */
	private static Logger logger = JLogger.getLogger(JConfig.class);

	/**
	 * Initialize our variable table
	 */
	static {
		Map<String, String> temp = new HashMap<String, String>();
		temp.put("jnp", JNP);
		temp.put("company", COMPANY);
		temp.put("suffix", SUFFIX);
		temp.put("A.A", "${B.B}");
		temp.put("B.B", "C.C");

		/*
		 * Lets make sure we don't modify this map in any of our tests otherwise it
		 * will have adverse effects on later run tests
		 */
		variables = Collections.unmodifiableMap(temp);

		properties = new Properties();
		properties.setProperty("a.b", "A.B");
		properties.setProperty("a.b.c", "A.B.C");
		properties.setProperty("a.b.c.d", "A.B.C.D");
		properties.setProperty("a.b.ext", "A.B.gotcha");

		properties.setProperty("a.a", "@{b.b}");
		properties.setProperty("b.b", "c.c");
	}

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
		logger.setLevel(Level.OFF);
	}

	/**
	 * Test name.
	 */
	public void testName() {
		ConfigString string = new ConfigString("${name}", variables, properties);
		assertTrue("sub failed in expand", string.expand("mark"));
		assertEquals("mark", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test name twice.
	 */
	public void testNameTwice() {
		ConfigString string = new ConfigString("${name}${name}", variables, properties);
		assertTrue("sub failed in expand", string.expand("mark"));
		assertEquals("markmark", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test name trice.
	 */
	public void testNameTrice() {
		ConfigString string = new ConfigString("${name}${name}-.sdfo.${name}", variables, properties);
		assertTrue("sub failed in expand", string.expand("mark"));
		assertEquals("markmark-.sdfo.mark", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test one variable.
	 */
	public void testOneVariable() {
		ConfigString string = new ConfigString("${jnp}", variables, properties);
		assertTrue("sub failed in expand", string.expand("mark", variables));
		assertEquals(JNP, string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test name and one variable.
	 */
	public void testNameAndOneVariable() {
		ConfigString string = new ConfigString("${jnp}.${name}", variables, properties);
		assertTrue("sub failed in expand", string.expand("mark", variables));
		assertEquals(JNP + ".mark", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test name and two variables.
	 */
	public void testNameAndTwoVariables() {
		ConfigString string = new ConfigString("${jnp}.${name}_${company}", variables, properties);
		assertTrue("sub failed in expand", string.expand("mark", variables));
		assertEquals(JNP + ".mark_" + COMPANY, string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test two names and two variables.
	 */
	public void testTwoNamesAndTwoVariables() {
		ConfigString string =
		    new ConfigString("${jnp}.${name}_${company} ${name}", variables, properties);
		assertTrue("sub failed in expand", string.expand("mark", variables));
		assertEquals(JNP + ".mark_" + COMPANY + " mark", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test one property.
	 */
	public void testOneProperty() {
		ConfigString string = new ConfigString("before @{a.b} after", variables, properties);
		assertTrue("sub failed in expand", string
		    .expand("mark", properties));
		assertEquals("before A.B after", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test two properties.
	 */
	public void testTwoProperties() {
		ConfigString string =
		    new ConfigString("before @{a.b} after @{a.b.c}", variables, properties);
		assertTrue("sub failed in expand", string
		    .expand("mark", properties));
		assertEquals("before A.B after A.B.C", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test two same properties.
	 */
	public void testTwoSameProperties() {
		ConfigString string = new ConfigString("before @{a.b} after @{a.b}", variables, properties);
		assertTrue("sub failed in expand", string
		    .expand("mark", properties));
		assertEquals("before A.B after A.B", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test one name and two properties.
	 */
	public void testOneNameAndTwoProperties() {
		ConfigString string =
		    new ConfigString("before @{a.b} ${name} @{a.b.c}", variables, properties);
		assertTrue("sub failed in expand", string
		    .expand("mark", properties));
		assertEquals("before A.B mark A.B.C", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test name within a property.
	 */
	public void testNameWithinAProperty() {
		ConfigString string = new ConfigString("@{a.${name}.c}", variables, properties);
		assertTrue("sub failed in expand", string.expand("b", properties));
		assertEquals("A.B.C", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test suffix variable within a property.
	 */
	public void testSUFFIXVariableWithinAProperty() {
		ConfigString string = new ConfigString("@{a.${name}${suffix}}", variables, properties);
		assertTrue("sub failed in expand", string.expand("b", variables,
		    properties));
		assertEquals("A.B.gotcha", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test recursive properties.
	 */
	public void testRecursiveProperties() {
		ConfigString string = new ConfigString("@{a.a}", variables, properties);
		assertTrue("sub failed in expand", string.expand("", variables,
		    properties));
		assertEquals("c.c", string.toString());

		string.reset(); // Reintialize
	}
	
	/**
	 * Test recursive variables.
	 */
	public void testRecursiveVariables() {
		ConfigString string = new ConfigString("${A.A}", variables, properties);
		assertTrue("sub failed in expand", string.expand("", variables,
		    properties));
		assertEquals("C.C", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test quotes.
	 */
	public void testQuotes() {
		ConfigString string = new ConfigString("'${A.A}'", variables, properties);
		assertTrue("sub failed in expand", string.expand("", variables,
		    properties));
		assertEquals("'${A.A}'", string.toString());

		string.reset(); // Reintialize
	}

	/**
	 * Test quotes twice.
	 */
	public void testQuotesTwice() {
		ConfigString string = new ConfigString("'${A.A}' and '@{a.${b}}'", variables, properties);
		assertTrue("sub failed in expand", string.expand("", variables,
		    properties));
		assertEquals("'${A.A}' and '@{a.${b}}'", string.toString());

		string.reset(); // Reintialize
	}
	
	/**
	 * Test quotes with escaped sub quote.
	 */
	public void testQuotesWithEscapedSubQuote() {
		ConfigString string = new ConfigString("'${A.\\'A}' and '@{a.${b}}'", variables, properties);
		assertTrue("sub failed in expand", string.expand("", variables,
		    properties));
		assertEquals("'${A.\\'A}' and '@{a.${b}}'", string.toString());

		string.reset(); // Reintialize
	}
	
	/**
	 * Test complex string.
	 */
	public void testComplexString() {
		String s = 
		"'File(@{$resolver}.${name}})' \\\r\n" + 
		"'File(@{$resolver}.dir}/${name}@{${resolver}.suffix})' \\\r\n" + 
		"'File(@{user.dir}/${name}@{${resolver}.suffix})' \\\r\n" + 
		"'File(@{user.home}/@{${resolver}.subdir}/${name}@{${resolver}.suffix})' \\\r\n" + 
		"'File(@{java.io.tmpdir}/${name}@{${resolver}.suffix})' \\\r\n" + 
		"'Classpath(${name}@{${resolver}.suffix})'\r\n" + 
		"";
		
		ConfigString string = new ConfigString(s, variables, properties);
		string.expand("mark", variables,
		    properties);
		
		string.remove("\r\n"); // won't remove escaped \r\n
		string.remove("\\\r\n");
		
//		System.out.println("\"" + string.toString() + "\"");
	}


}
