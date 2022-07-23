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
package org.jnetpcap.packet.structure;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * A JField that is filled in with preset values.
 * 
 * @author Sly Technologies, Inc.
 */
public class DefaultJField extends JField {

	/** The display. */
	private String display;

	/** The length. */
	private int length;

	/** The mask. */
	private long mask;

	/** The name. */
	private String name;

	/** The nicname. */
	private String nicname;

	/** The offset. */
	private int offset;

	/** The priority. */
	private Priority priority = Priority.MEDIUM;

	/** The style. */
	private Style style = Style.STRING;

	/** The sub fields. */
	private JField[] subFields;

	/** The units. */
	private String units;

	/** The value. */
	private Object value;

	/** The value description. */
	private String valueDescription;

	public DefaultJField() {
		super();
	}

	public DefaultJField(String name) {
		this.name = name;
	}

	public DefaultJField(String name, int offset, int length) {
		this.name = name;
	}

	public DefaultJField(JField parent) {
		super(parent);
	}

	/**
	 * Gets the display.
	 * 
	 * @return the display
	 */
	public String getDisplay() {
		return display;
	}

	/**
	 * Gets the display.
	 * 
	 * @param header
	 *          the header
	 * @return the display
	 * @see org.jnetpcap.packet.structure.JField#getDisplay(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public String getDisplay(JHeader header) {
		return display;
	}

	/**
	 * Gets the length.
	 * 
	 * @return the length
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Gets the length.
	 * 
	 * @param header
	 *          the header
	 * @return the length
	 * @see org.jnetpcap.packet.structure.JField#getLength(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public int getLength(JHeader header) {
		return length;
	}

	/**
	 * Gets the mask.
	 * 
	 * @return the mask
	 */
	public long getMask() {
		return mask;
	}

	/**
	 * Gets the mask.
	 * 
	 * @param header
	 *          the header
	 * @return the mask
	 * @see org.jnetpcap.packet.structure.JField#getMask(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public long getMask(JHeader header) {
		return mask;
	}

	/**
	 * Gets the name.
	 * 
	 * @return the name
	 * @see org.jnetpcap.packet.structure.JField#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Gets the nicname.
	 * 
	 * @return the nicname
	 * @see org.jnetpcap.packet.structure.JField#getNicname()
	 */
	@Override
	public String getNicname() {
		return nicname;
	}

	/**
	 * Gets the offset.
	 * 
	 * @return the offset
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * Gets the offset.
	 * 
	 * @param header
	 *          the header
	 * @return the offset
	 * @see org.jnetpcap.packet.structure.JField#getOffset(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public int getOffset(JHeader header) {
		return offset;
	}

	/**
	 * Gets the priority.
	 * 
	 * @return the priority
	 * @see org.jnetpcap.packet.structure.JField#getPriority()
	 */
	@Override
	public Priority getPriority() {
		return priority;
	}

	/**
	 * Gets the style.
	 * 
	 * @return the style
	 * @see org.jnetpcap.packet.structure.JField#getStyle()
	 */
	@Override
	public Style getStyle() {
		return style;
	}

	/**
	 * Gets the sub fields.
	 * 
	 * @return the sub fields
	 * @see org.jnetpcap.packet.structure.JField#getSubFields()
	 */
	@Override
	public JField[] getSubFields() {
		return subFields;
	}

	/**
	 * Gets the units.
	 * 
	 * @return the units
	 */
	public String getUnits() {
		return units;
	}

	/**
	 * Gets the units.
	 * 
	 * @param header
	 *          the header
	 * @return the units
	 * @see org.jnetpcap.packet.structure.JField#getUnits(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public String getUnits(JHeader header) {
		return units;
	}

	/**
	 * Gets the value.
	 * 
	 * @return the value
	 */
	public Object getValue() {
		return value;
	}

	/**
	 * Gets the value.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param c
	 *          the c
	 * @param header
	 *          the header
	 * @return the value
	 * @see org.jnetpcap.packet.structure.JField#getValue(java.lang.Class,
	 *      org.jnetpcap.packet.JHeader)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public <T> T getValue(Class<T> c, JHeader header) {
		return (T) value;
	}

	/**
	 * Gets the value.
	 * 
	 * @param header
	 *          the header
	 * @return the value
	 * @see org.jnetpcap.packet.structure.JField#getValue(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public Object getValue(JHeader header) {
		return value;
	}

	/**
	 * Gets the value description.
	 * 
	 * @return the valueDescription
	 */
	public String getValueDescription() {
		return valueDescription;
	}

	/**
	 * Gets the value description.
	 * 
	 * @param header
	 *          the header
	 * @return the value description
	 * @see org.jnetpcap.packet.structure.JField#getValueDescription(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public String getValueDescription(JHeader header) {
		return valueDescription;
	}

	/**
	 * Checks for field.
	 * 
	 * @param header
	 *          the header
	 * @return true, if successful
	 * @see org.jnetpcap.packet.structure.JField#hasField(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public boolean hasField(JHeader header) {
		return true;
	}

	/**
	 * Checks for sub fields.
	 * 
	 * @return true, if successful
	 * @see org.jnetpcap.packet.structure.JField#hasSubFields()
	 */
	@Override
	public boolean hasSubFields() {
		return subFields != null;
	}

	/**
	 * Long value.
	 * 
	 * @param header
	 *          the header
	 * @return the long
	 * @see org.jnetpcap.packet.structure.JField#longValue(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public long longValue(JHeader header) {
		return getValue(Long.class, header);
	}

	/**
	 * Sets the display.
	 * 
	 * @param display
	 *          the display to set
	 */
	public void setDisplay(String display) {
		this.display = display;
	}

	/**
	 * Sets the length.
	 * 
	 * @param length
	 *          the length to set
	 */
	public void setLength(int length) {
		this.length = length;
	}

	/**
	 * Sets the mask.
	 * 
	 * @param mask
	 *          the mask to set
	 */
	public void setMask(long mask) {
		this.mask = mask;
	}

	/**
	 * Sets the name.
	 * 
	 * @param name
	 *          the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Sets the nicname.
	 * 
	 * @param nicname
	 *          the nicname to set
	 */
	public void setNicname(String nicname) {
		this.nicname = nicname;
	}

	/**
	 * Sets the offset.
	 * 
	 * @param offset
	 *          the offset to set
	 */
	public void setOffset(int offset) {
		this.offset = offset;
	}

	/**
	 * Sets the priority.
	 * 
	 * @param priority
	 *          the priority to set
	 */
	public void setPriority(Priority priority) {
		this.priority = priority;
	}

	/**
	 * Sets the style.
	 * 
	 * @param style
	 *          the new style
	 * @see org.jnetpcap.packet.structure.JField#setStyle(org.jnetpcap.packet.format.JFormatter.Style)
	 */
	@Override
	public void setStyle(Style style) {
		this.style = style;
	}

	/**
	 * Sets the sub fields.
	 * 
	 * @param subFields
	 *          the subFields to set
	 */
	public void setSubFields(JField[] subFields) {
		this.subFields = subFields;
	}

	/**
	 * Sets the units.
	 * 
	 * @param units
	 *          the units to set
	 */
	public void setUnits(String units) {
		this.units = units;
	}

	/**
	 * Sets the value.
	 * 
	 * @param value
	 *          the value to set
	 */
	public void setValue(Object value) {
		this.value = value;
	}

	/**
	 * Sets the value description.
	 * 
	 * @param valueDescription
	 *          the valueDescription to set
	 */
	public void setValueDescription(String valueDescription) {
		this.valueDescription = valueDescription;
	}

}
