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
package org.jnetpcap.newstuff;

import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.structure.JField;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class JFieldMap {
	
	/** The field map. */
	private Map<String, JField> fieldMap;

	/**
	 * Checks for field.
	 * 
	 * @param field
	 *          the field
	 * @return true, if successful
	 */
	protected boolean hasField(Enum<? extends Enum<?>> field) {
		return fieldMap.containsKey(field);
	}

	/**
	 * Field description.
	 * 
	 * @param field
	 *          the field
	 * @param header
	 *          the header
	 * @return the string
	 */
	protected String fieldDescription(Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field).getValueDescription(header);
	}

	/**
	 * Field length.
	 * 
	 * @param field
	 *          the field
	 * @param header
	 *          the header
	 * @return the int
	 */
	protected int fieldLength(Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field).getLength(header);
	}

	/**
	 * Field offset.
	 * 
	 * @param field
	 *          the field
	 * @param header
	 *          the header
	 * @return the int
	 */
	protected int fieldOffset(Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field).getOffset(header);
	}

	/**
	 * Field value.
	 * 
	 * @param field
	 *          the field
	 * @param header
	 *          the header
	 * @return the object
	 */
	protected Object fieldValue(Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field.name()).getValue(header);
	}

	/**
	 * Field value.
	 * 
	 * @param <V>
	 *          the value type
	 * @param c
	 *          the c
	 * @param field
	 *          the field
	 * @param header
	 *          the header
	 * @return the v
	 */
	protected <V> V fieldValue(Class<V> c, Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field).getValue(c, header);
	}

	/**
	 * Field array.
	 * 
	 * @param header
	 *          the header
	 * @return the string[]
	 */
	public String[] fieldArray(final JHeader header) {

		final String[] r = fieldMap.keySet().toArray(new String[fieldMap.size()]);

		Arrays.sort(r, new Comparator<String>() {

			public int compare(String o1, String o2) {
				return fieldMap.get(o1).getOffset(header)
				    - fieldMap.get(o2).getOffset(header);
			}

		});

		return r;
	}
	
	/**
	 * Adds the field.
	 * 
	 * @param field
	 *          the field
	 * @param value
	 *          the value
	 * @param offset
	 *          the offset
	 */
	public void addField(
	    Enum<? extends Enum<?>> field,
	    String value,
	    int offset) {
		addField(field, value, offset, value.length());
	}

	/**
	 * Adds the field.
	 * 
	 * @param field
	 *          the field
	 * @param value
	 *          the value
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 */
	public void addField(
	    Enum<? extends Enum<?>> field,
	    String value,
	    int offset,
	    int length) {
		this.fieldMap.put(field.name(), null);
	}

	/**
	 * Adds the field.
	 * 
	 * @param name
	 *          the name
	 * @param value
	 *          the value
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 */
	public void addField(String name, String value, int offset, int length) {
		this.fieldMap.put(name, null);
	}

	/**
	 * Clear fields.
	 */
	public void clearFields() {
		this.fieldMap.clear();
	}

}
