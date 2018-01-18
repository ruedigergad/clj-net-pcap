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
package org.jnetpcap.protocol.tcpip.radius;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.protocol.tcpip.Radius.AVType;
import org.jnetpcap.protocol.tcpip.radius.FreeRadiusTokenizer.TokenType;

/**
 * FreeRADIUS project dictionary reader.
 * <p>
 * Based on the dictionary file format specification:
 * http://freeradius.org/radiusd/man/dictionary.html
 * </p>
 * 
 * @author Sly Technologies, Inc.
 * @see http://freeradius.org/radiusd/man/dictionary.html
 */
public class FreeRadiusDictionary {

	public static class Attribute {
		public long code;
		public final String name;
		public String typeString;
		public AVType type;
		public final Map<Long, String> values = new HashMap<Long, String>();

		public Attribute(long code, String name, String typeString) {
			this.code = code;
			this.name = name;
			this.typeString = typeString;
			this.type = AVType.parseAVType(typeString);
		}

		@Override
		public String toString() {
			if (typeString == null) {
				return String.format("%s(TEMPORARY_CODE=0X%X):NOT_DEFINED_YET",
						name,
						code);

			} else {
				return String.format("%s(%d):%s", name, code, typeString);
			}
		}
	}

	public static class Attributes extends HashMap<Long, Attribute> {

		private static final long serialVersionUID = 5690140802351434597L;

		public boolean hasAttribute(String name) {
			for (Attribute at : values()) {
				if (at.name.equals(name)) {
					return true;
				}
			}

			return false;
		}

		public Attribute put(long code, String name, String type) {
			Attribute a;
			if (hasAttribute(name)) {
				a = valueOf(name);
				remove(a.code);

				a.code = code;
				a.typeString = type;
				// System.out.printf("WARNING: changing code and type of attribute %s\n",
				// a);
			} else {
				a = new Attribute(code, name, type);
			}
			super.put(code, a);

			return a;
		}

		public Attribute valueOf(String name) {
			for (Attribute at : values()) {
				if (at.name.equals(name)) {
					return at;
				}
			}

			Attribute at = new Attribute(name.hashCode(), name, null);
			put(at.code, at);

			return at;
		}
	}

	public static class Vendor {
		public final Attributes attributes = new Attributes();
		public final long code;
		public final int lenLen;
		public final String name;
		public final int typeLen;

		public Vendor(String name, long code) {
			this.name = name;
			this.code = code;
			this.typeLen = 1;
			this.lenLen = 1;
		}

		public Vendor(String name, long code, int typeLen, int lenLen) {
			this.name = name;
			this.code = code;
			this.typeLen = typeLen;
			this.lenLen = lenLen;
		}

		@Override
		public String toString() {
			return String.format("%s(%d) format=%d,%d", name, code, typeLen, lenLen);
		}
	}

	public static class Vendors extends HashMap<Long, Vendor> {

		private static final long serialVersionUID = 9089071071454562950L;

		public Vendor put(long code, String name) {
			Vendor v = new Vendor(name, code);
			put(code, v);

			return v;
		}

		public Vendor put(long code, String name, int typeLen, int lenLen) {
			Vendor v = new Vendor(name, code, typeLen, lenLen);
			put(code, v);

			return v;
		}

		public Vendor valueOf(String name) {
			for (Vendor v : values()) {
				if (name.equals(v.name)) {
					return v;
				}
			}

			return null;
		}
	}

	private static final TokenType ATTRIBUTE = TokenType.ATTRIBUTE;

	private static final TokenType EOL = TokenType.EOL;

	private static final TokenType ID = TokenType.ID;

	private static final TokenType INCLUDE = TokenType.INCLUDE;

	private static final TokenType NUM = TokenType.NUMBER;

	private final static String RESOURCE_ROOT =
			"org/jnetpcap/protocol/tcpip/radius/";

	private static final TokenType TYPE = TokenType.VALUE_TYPE;

	public final Attributes attributes = new Attributes();

	private final Vendors vendors = new Vendors();

	private boolean verbose = false;

	public FreeRadiusDictionary() {
		this("dictionary");
	}

	public FreeRadiusDictionary(String resource) {
		this(RESOURCE_ROOT, resource);
	}

	public FreeRadiusDictionary(String root, String resource) {
		if (root.endsWith("/") == false) {
			root = root + "/";
		}

	}

	public Attribute attribute(int id) {

		return attributes.get(id);
	}

	public Attribute attribute(int vendor, int id) {
		Attributes at = vendors.get(vendor).attributes;
		if (at == null) {
			return null;
		}

		return at.get(id);
	}

	private InputStream openResource(String path) {
		InputStream in =
				FreeRadiusDictionary.class.getClassLoader().getResourceAsStream(path);
		return in;
	}

	public boolean process() throws IOException {
		return process(RESOURCE_ROOT, "dictionary");
	}

	public boolean process(String resource) throws IOException {
		return process(RESOURCE_ROOT, resource);
	}

	public boolean process(String root, String resource) throws IOException {
		InputStream in = openResource(root + resource);
		if (in == null) {
			return false;
		}

		FreeRadiusTokenizer tokens = new FreeRadiusTokenizer(in);

		int t = 1; // Vendor type field length in bytes
		int l = 1; // Vendor length field length in bytes
		Vendor vendor = null;
		boolean vendorSection = false;

		while (tokens.hasNextToken()) {
			if (tokens.predicate(EOL)) {
				tokens.consume();
				continue; // Skip empty lines
			}

			/*
			 * $INCLUDE id
			 */
			if (tokens.predicate(INCLUDE, ID, EOL)) {

				String includeResource = tokens.get(null, ID, null).stringValue();

				if (verbose) {
					System.out.printf("INCLUDE=%s root=%s\n", includeResource, root);
				}
				process(root, includeResource);

				continue;
			}

			/*
			 * ATTRIBUTE ID NUMBER VALUE_TYPE EOL
			 */
			if (tokens.predicate(ATTRIBUTE, ID, NUM, TYPE, EOL)) {
				String name = tokens.get(null, ID).stringValue();
				int code = tokens.get().intValue();
				String type = tokens.get(ID, null).stringValue();

				if (vendor != null) {
					Attribute at = vendor.attributes.put(code, name, type);
					if (verbose) {
						System.out.printf("VENDOR(%s): ATTRIBUTE=%s\n", vendor.name, at);
					}

				} else {
					Attribute at = attributes.put(code, name, type);
					if (verbose) {
						System.out.printf("ATTRIBUTE=%s\n", at);
					}
				}

				if (vendorSection == false) {
					vendor = null;
				}

				continue;
			}

			/*
			 * ATTRIBUTE ID NUMBER VALUE_TYPE VENDOR EOL
			 */
			if (tokens.predicate(ATTRIBUTE, ID, NUM, TYPE, ID, EOL)) {

				String name = tokens.get(null, ID).stringValue();
				long code = tokens.get().longValue();
				String type = tokens.get(ID, null).stringValue();
				vendor = vendors.valueOf(tokens.get().stringValue());

				Attribute at = vendor.attributes.put(code, name, type);
				if (verbose) {
					System.out.printf("VENDOR(%s): ATTRIBUTE=%s\n", vendor.name, at);
				}

				continue;
			}

			/*
			 * VALUE ID NUMBER VALUE_TYPE VENDOR EOL
			 */
			if (tokens.predicate(TokenType.VALUE, ID, ID, NUM, EOL)) {

				String attributeName = tokens.get(null, ID).stringValue();
				String valueName = tokens.get().stringValue();
				long code = tokens.get(NUM, null).longValue();

				Attributes attributes =
						(vendor == null) ? this.attributes : vendor.attributes;

				Attribute at = attributes.valueOf(attributeName);
				if (at == null) {
					if (verbose) {
						System.out.printf("ERROR: %s not found in %s; VALUE=%s(%d)\n",
								attributeName,
								resource,
								valueName,
								code);
					}
					continue;
				}

				at.values.put(code, valueName);
				if (verbose && vendor == null) {
					System.out.printf("%s VALUE=%s(%d)\n", at, valueName, code);
				} else if (verbose && vendor != null) {
					System.out.printf("VENDOR(%s): %s VALUE=%s(%d)\n",
							vendor.name,
							at,
							valueName,
							code);
				}

				continue;
			}

			/*
			 * VENDOR ID NUMBER FORMAT NUMBER NUMBER EOL
			 */
			if (tokens.predicate(TokenType.VENDOR,
					ID,
					NUM,
					TokenType.FORMAT,
					NUM,
					NUM,
					EOL)) {

				String name = tokens.get(null, ID).stringValue();
				long code = tokens.get(NUM).longValue();
				t = tokens.get(null, NUM).intValue();
				l = tokens.get(NUM, null).intValue();

				vendor = vendors.put(code, name, t, l);
				if (verbose) {
					System.out.printf("VENDOR: %s\n", vendor);
				}
				vendor = null;
				continue;
			}

			/*
			 * VENDOR ID NUMBER EOL
			 */
			if (tokens.predicate(TokenType.VENDOR, ID, NUM, EOL)) {

				String name = tokens.get(null, ID).stringValue();
				long code = tokens.get(NUM, null).longValue();

				vendor = vendors.put(code, name, t, l);
				if (verbose) {
					System.out.printf("VENDOR: %s\n", vendor);
				}
				vendor = null;
				continue;
			}

			/*
			 * BEGIN_VENDOR ID EOL
			 */
			if (tokens.predicate(TokenType.BEGIN_VENDOR, ID, EOL)) {
				vendor = vendors.valueOf(tokens.get(null, ID, null).stringValue());
				vendorSection = true;

				if (verbose) {
					System.out.printf("BEGIN-VENDOR(%s)\n", vendor.name);
				}
				continue;
			}

			/*
			 * END_VENDOR ID EOL
			 */
			if (tokens.predicate(TokenType.END_VENDOR, ID, EOL)) {
				String name = tokens.get(null, ID, null).stringValue();
				vendor = null;
				vendorSection = false;
				if (verbose) {
					System.out.printf("END-VENDOR(%s)\n", name);
				}
				continue;
			}

			tokens.consume();
		}

		return true;
	}

	public void setVerbose(boolean state) {
		this.verbose = state;
	}

	public String value(int attribute, int value) {

		Attribute at = attribute(attribute);

		return at.values.get(value);
	}

	public String value(int vendor, int attribute, int value) {
		Attribute at = attribute(vendor, attribute);

		return at.values.get(value);
	}

	/**
	 * @param vendor
	 * @return
	 */
	public Vendor vendor(long code) {
		return vendors.get(code);
	}

}
