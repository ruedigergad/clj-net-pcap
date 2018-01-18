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
package org.jnetpcap.util.config;

import java.util.Map;
import java.util.Properties;

import org.jnetpcap.util.ExpandableString;

// TODO: Auto-generated Javadoc
/**
 * Expandable string that allows configuration variables and properties to be
 * expanded.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class ConfigString
    extends ExpandableString {
	
	/** The Constant VO. */
	private final static String VO = "${"; // Variable Open

	/** The Constant VC. */
	private final static String VC = "}"; // Variable Close

	/** The Constant PO. */
	private final static String PO = "@{"; // Property Open

	/** The Constant PC. */
	private final static String PC = "}"; // Property Close

	/** The variables. */
	private final Map<String, String> variables;

	/** The properties. */
	private final Properties properties;

	// private final static String VO =
	// JConfig.getProperty("config.syntax.variable.open", "${");
	//
	// private final static String VC =
	// JConfig.getProperty("config.syntax.variable.close", "}");
	//
	// private final static String PO =
	// JConfig.getProperty("config.syntax.property.open", "@{");
	//
	// private final static String PC =
	// JConfig.getProperty("config.syntax.property.close", "}");

	/**
	 * Instantiates a new config string.
	 * 
	 * @param template
	 *          the template
	 * @param variables
	 *          the variables
	 * @param properties
	 *          the properties
	 */
	public ConfigString(String template, Map<String, String> variables,
	    Properties properties) {
		super(template);
		this.variables = variables;
		this.properties = properties;
	}

	/**
	 * Expand.
	 * 
	 * @param name
	 *          the name
	 * @return true, if successful
	 */
	public boolean expand(String name) {
		return expand(name, variables, properties);
	}

	/**
	 * Expand.
	 * 
	 * @param name
	 *          the name
	 * @param variables
	 *          the variables
	 * @return true, if successful
	 */
	public boolean expand(String name, Map<String, String> variables) {
		return expand(name, variables, properties);
	}

	/**
	 * Expand.
	 * 
	 * @param name
	 *          the name
	 * @param variables
	 *          the variables
	 * @param properties
	 *          the properties
	 * @return true, if successful
	 */
	public boolean expand(
	    String name,
	    Map<String, String> variables,
	    Properties properties) {
		if (saveQuotes() == false) {
			return false;
		}

		count = 0;

		while (expandVariables(name, variables, properties)
		    && expandProperties(name, variables, properties)) {

			/*
			 * count keeps track of how many expansions happened. When it stays at 0
			 * after calling expand* that means that there was nothing in the string
			 * to expand and there were no failures.
			 */
			if (count == 0) {
				restoreQuotes();
				return true;
			}

			count = 0;
		}

		restoreQuotes();
		/*
		 * Any failure, unmatched, @ or $ sign, property or variable not found, will
		 * break us out of the loop and we report failure.
		 */
		return false;
	}

	/**
	 * Expand.
	 * 
	 * @param name
	 *          the name
	 * @param properties
	 *          the properties
	 * @return true, if successful
	 */
	public boolean expand(String name, Properties properties) {
		return expand(name, null, properties);
	}

	/**
	 * Expand properties.
	 * 
	 * @param name
	 *          the name
	 * @param variables
	 *          the variables
	 * @param properties
	 *          the properties
	 * @return true, if successful
	 */
	public boolean expandProperties(
	    String name,
	    Map<String, String> variables, Properties properties) {

		while (scanNext(PO, PC) && start != -1) {
			if (properties == null) {
				return false;
			}

			String property = super.substring(start + PO.length(), end);
			String value = properties.getProperty(property);
			if (value != null) {
				super.replace(start, end + VC.length(), value);
			} else {
				return false;
			}
			
			if (saveQuotes() == false) {
				return false;
			}
			
			if (expandVariables(name, variables, properties) == false) {
				return false;
			}
		}

		return (start == -1) ? true : false;
	}

	/**
	 * Replaces variables and properties with their values, and null if anything
	 * is not defined.
	 * 
	 * @param name
	 *          special name variable that will replace $name$ in the string
	 * @param variables
	 *          the variables
	 * @param properties
	 *          properties
	 * @return resulting string with all substitutions complete or null if any
	 *         substitution failed such as undefined referenced property
	 */
	public boolean expandVariables(
	    String name,
	    Map<String, String> variables,
	    Properties properties) {

		while (scanNext(VO, VC) && start != -1) {

			String variable = super.substring(start + VO.length(), end);
			if (variable.equals("name")) {
				super.replace(start, end + VC.length(), name);

			} else if (variables != null && variables.containsKey(variable)) {
				super.replace(start, end + 1, variables.get(variable));

			} else {
				return false;
			}
		}

		return (start == -1) ? true : false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.config.ExpandableString#reset()
	 */
	/**
	 * Reset.
	 * 
	 * @return the config string
	 * @see org.jnetpcap.util.ExpandableString#reset()
	 */
	@Override
	public ConfigString reset() {
		super.reset();

		return this;
	}

}
