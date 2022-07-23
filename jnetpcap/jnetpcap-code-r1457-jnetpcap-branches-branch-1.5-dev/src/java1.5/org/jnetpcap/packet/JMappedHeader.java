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

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class JMappedHeader.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JMappedHeader extends JHeader {

	/**
	 * Instantiates a new j mapped header.
	 */
	public JMappedHeader() {
	}

	/**
	 * Instantiates a new j mapped header.
	 * 
	 * @param protocol
	 *            the protocol
	 */
	public JMappedHeader(JProtocol protocol) {
		super(protocol);
	}

	/**
	 * Instantiates a new j mapped header.
	 * 
	 * @param id
	 *            the id
	 * @param fields
	 *            the fields
	 * @param name
	 *            the name
	 */
	public JMappedHeader(int id, JField[] fields, String name) {
		super(id, fields, name);
	}

	/**
	 * Instantiates a new j mapped header.
	 * 
	 * @param id
	 *            the id
	 * @param fields
	 *            the fields
	 * @param name
	 *            the name
	 * @param nicname
	 *            the nicname
	 */
	public JMappedHeader(int id, JField[] fields, String name, String nicname) {
		super(id, fields, name, nicname);
	}

	/**
	 * Instantiates a new j mapped header.
	 * 
	 * @param id
	 *            the id
	 * @param name
	 *            the name
	 */
	public JMappedHeader(int id, String name) {
		super(id, name);
	}

	/**
	 * Instantiates a new j mapped header.
	 * 
	 * @param id
	 *            the id
	 * @param name
	 *            the name
	 * @param nicname
	 *            the nicname
	 */
	public JMappedHeader(int id, String name, String nicname) {
		super(id, name, nicname);
	}

	/**
	 * Instantiates a new j mapped header.
	 * 
	 * @param state
	 *            the state
	 * @param fields
	 *            the fields
	 * @param name
	 *            the name
	 * @param nicname
	 *            the nicname
	 */
	public JMappedHeader(State state, JField[] fields, String name,
			String nicname) {
		super(state, fields, name, nicname);
	}

	/**
	 * The Class Entry.
	 */
	private static class Entry {

		/** The description. */
		private final String description;

		/** The display. */
		private final String display;

		/** The length. */
		private final int length;

		/** The offset. */
		private final int offset;

		/** The value. */
		private final Object value;

		/**
		 * Instantiates a new entry.
		 * 
		 * @param value
		 *            the value
		 * @param offset
		 *            the offset
		 * @param length
		 *            the length
		 * @param display
		 *            the display
		 * @param description
		 *            the description
		 */
		public Entry(Object value, int offset, int length, String display,
				String description) {
			this.value = value;
			this.offset = offset;
			this.length = length;
			this.display = display;
			this.description = description;
		}

		/**
		 * Gets the value description.
		 * 
		 * @param mappedHeader
		 *            the mapped header
		 * @return the value description
		 */
		public String getValueDescription(JHeader mappedHeader) {
			return description;
		}

		/**
		 * Gets the length.
		 * 
		 * @param mappedHeader
		 *            the mapped header
		 * @return the length
		 */
		public int getLength(JMappedHeader mappedHeader) {
			return length;
		}

		/**
		 * Gets the display.
		 * 
		 * @param mappedHeader
		 *            the mapped header
		 * @return the display
		 */
		public String getDisplay(JMappedHeader mappedHeader) {
			return display;
		}

		/**
		 * Gets the offset.
		 * 
		 * @param mappedHeader
		 *            the mapped header
		 * @return the offset
		 */
		public int getOffset(JMappedHeader mappedHeader) {
			return offset;
		}

		/**
		 * Gets the value.
		 * 
		 * @param mappedHeader
		 *            the mapped header
		 * @return the value
		 */
		public Object getValue(JMappedHeader mappedHeader) {
			return value;
		}

		/**
		 * Gets the value.
		 * 
		 * @param <V>
		 *            the value type
		 * @param c
		 *            the c
		 * @param mappedHeader
		 *            the mapped header
		 * @return the value
		 */
		@SuppressWarnings("unchecked")
		public <V> V getValue(Class<V> c, JMappedHeader mappedHeader) {
			return (V) value;
		}

	}

	/** The field map. */
	private final Map<String, Entry> fieldMap = new HashMap<String, Entry>(50);

	/**
	 * Checks for field.
	 * 
	 * @param field
	 *            the field
	 * @return true, if successful
	 */
	protected boolean hasField(Enum<? extends Enum<?>> field) {
		return fieldMap.containsKey(map(field));
	}

	/**
	 * Checks for field.
	 * 
	 * @param field
	 *            the field
	 * @return true, if successful
	 */
	@Dynamic(Field.Property.CHECK)
	protected boolean hasField(String field) {
		return fieldMap.containsKey(map(field));
	}

	/**
	 * Field description.
	 * 
	 * @param field
	 *            the field
	 * @return the string
	 */
	protected String fieldDescription(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getValueDescription(this);
	}

	/**
	 * Field description.
	 * 
	 * @param field
	 *            the field
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	protected String fieldDescription(String field) {
		return fieldMap.get(map(field)).getValueDescription(this);
	}

	/**
	 * Field display.
	 * 
	 * @param field
	 *            the field
	 * @return the string
	 */
	protected String fieldDisplay(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getDisplay(this);
	}

	/**
	 * Field display.
	 * 
	 * @param field
	 *            the field
	 * @return the string
	 */
	@Dynamic(Field.Property.DISPLAY)
	protected String fieldDisplay(String field) {
		return fieldMap.get(map(field)).getDisplay(this);
	}

	/**
	 * Field length.
	 * 
	 * @param field
	 *            the field
	 * @return the int
	 */
	protected int fieldLength(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getLength(this);
	}

	/**
	 * Field length.
	 * 
	 * @param field
	 *            the field
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	protected int fieldLength(String field) {
		return fieldMap.get(map(field)).getLength(this);
	}

	/**
	 * Field offset.
	 * 
	 * @param field
	 *            the field
	 * @return the int
	 */
	protected int fieldOffset(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getOffset(this);
	}

	/**
	 * Map.
	 * 
	 * @param field
	 *            the field
	 * @return the string
	 */
	protected String map(Enum<? extends Enum<?>> field) {
		String s = field.name().replace('_', '-').toUpperCase();
		// System.out.printf("JMappedHeader::map(%s)=%s\n", field.name(), s);
		return s;
	}

	/**
	 * Map.
	 * 
	 * @param field
	 *            the field
	 * @return the string
	 */
	protected String map(String field) {
		String s = field.toUpperCase();
		// System.out.printf("JMappedHeader::map(%s)=%s\n", field, s);
		return s;
	}

	/**
	 * Field offset.
	 * 
	 * @param field
	 *            the field
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	protected int fieldOffset(String field) {
		if (fieldMap.get(map(field)) == null) {
			return -1;
		}

		return fieldMap.get(map(field)).getOffset(this);
	}

	/**
	 * Field value.
	 * 
	 * @param field
	 *            the field
	 * @return the object
	 */
	protected Object fieldValue(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getValue(this);
	}

	/**
	 * Field value.
	 * 
	 * @param field
	 *            the field
	 * @return the object
	 */
	@Dynamic(Field.Property.VALUE)
	protected Object fieldValue(String field) {
		return fieldMap.get(map(field)).getValue(this);
	}

	/**
	 * Field value.
	 * 
	 * @param <V>
	 *            the value type
	 * @param c
	 *            the c
	 * @param field
	 *            the field
	 * @return the v
	 */
	protected <V> V fieldValue(Class<V> c, Enum<? extends Enum<?>> field) {
		Entry entry = fieldMap.get(map(field));
		if (entry == null) {
			return null;
		}

		return entry.getValue(c, this);
	}

	/**
	 * Field value.
	 * 
	 * @param <V>
	 *            the value type
	 * @param c
	 *            the c
	 * @param field
	 *            the field
	 * @return the v
	 */
	protected <V> V fieldValue(Class<V> c, String field) {
		return fieldMap.get(map(field)).getValue(c, this);
	}

	/**
	 * Field array.
	 * 
	 * @return the string[]
	 */
	public String[] fieldArray() {

		final String[] r = fieldMap.keySet().toArray(
				new String[fieldMap.size()]);

		Arrays.sort(r, new Comparator<String>() {

			public int compare(String o1, String o2) {
				return fieldMap.get(o1).getOffset(JMappedHeader.this)
						- fieldMap.get(o2).getOffset(JMappedHeader.this);
			}

		});

		return r;
	}

	/**
	 * Adds the field.
	 * 
	 * @param field
	 *            the field
	 * @param value
	 *            the value
	 * @param offset
	 *            the offset
	 */
	public void addField(Enum<? extends Enum<?>> field, String value, int offset) {
		addField(field, value, offset, value.length());
	}

	/**
	 * Adds the field.
	 * 
	 * @param field
	 *            the field
	 * @param value
	 *            the value
	 * @param offset
	 *            the offset
	 * @param length
	 *            the length
	 */
	public void addField(Enum<? extends Enum<?>> field, String value,
			int offset, int length) {
		this.fieldMap.put(map(field),
				new Entry(value, offset, length, field.name(), null));
	}

	/**
	 * Adds the field.
	 * 
	 * @param name
	 *            the name
	 * @param value
	 *            the value
	 * @param offset
	 *            the offset
	 * @param length
	 *            the length
	 */
	public void addField(String name, String value, int offset, int length) {
		this.fieldMap.put(name, new Entry(value, offset, length, name, null));
	}

	/**
	 * Clear fields.
	 */
	public void clearFields() {
		this.fieldMap.clear();
	}

	/**
	 * Gets any AVP (Attribute-Value-Pair) by name.
	 * 
	 * @param name
	 *            name of the avp
	 * @return String value of the entry or null if not found
	 * @since 1.4
	 */
	public String getAVP(String name) {
		return (String) fieldValue(name);
	}

	/**
	 * Checks if a named AVP (Attribute-Value-Pair) is present within the
	 * header.
	 * 
	 * @param name
	 *            name of the avp
	 * @return true if AVP is found, otherwise false
	 * @since 1.4
	 */
	public boolean hasAVP(String name) {
		return hasField(name);
	}
}
