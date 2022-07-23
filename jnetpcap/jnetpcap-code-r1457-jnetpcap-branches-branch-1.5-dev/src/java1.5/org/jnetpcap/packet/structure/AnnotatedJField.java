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
package org.jnetpcap.packet.structure;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * @author Sly Technologies, Inc.
 * 
 */
public class AnnotatedJField extends JField {

	/**
	 * From annotated field.
	 * 
	 * @param field
	 *          the field
	 * @return the default field
	 */
	public static AnnotatedJField fromAnnotatedField(AnnotatedField field) {

		AnnotatedJField[] children =
				new AnnotatedJField[field.getSubFields().size()];
		int i = 0;
		for (AnnotatedField f : field.getSubFields()) {
			children[i++] = fromAnnotatedField(f);
		}

		AnnotatedJField.sortFieldByOffset(children, null, false);

		return new AnnotatedJField(field, children);
	}

	/**
	 * From annotated fields.
	 * 
	 * @param fields
	 *          the fields
	 * @return the j field[]
	 */
	public static JField[] fromAnnotatedFields(AnnotatedField[] fields) {
		JField[] f = new JField[fields.length];

		for (int i = 0; i < fields.length; i++) {
			f[i] = fromAnnotatedField(fields[i]);
		}

		return f;
	}

	/** The sub fields. */
	protected JField[] subFields;

	/** Name of the field which is also its ID. */
	private final String name;

	/** The nicname. */
	private final String nicname;

	/** The priority. */
	private final Priority priority;

	/** The style. */
	protected Style style;

	/** The value. */
	private final AnnotatedFieldMethod value;

	/** The offset. */
	private final AnnotatedFieldMethod offset;

	/** The length. */
	private final AnnotatedFieldMethod length;

	/** The display. */
	private final AnnotatedFieldMethod display;

	/** The description. */
	private final AnnotatedFieldMethod description;

	/** The mask. */
	private final AnnotatedFieldMethod mask;

	/** The check. */
	private final AnnotatedFieldMethod check;

	/** The units. */
	private final AnnotatedFieldMethod units;

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder b = new StringBuilder();

		b.append("name=").append(name);
		b.append(", nicname=").append(nicname);
		b.append(", parent=").append(getParent());
		b.append(", priority=").append(priority);
		b.append(", style=").append(style);

		return b.toString();
	}

	/**
	 * Instantiates a new j field.
	 * 
	 * @param afield
	 *          the afield
	 * @param children
	 *          the children
	 */
	public AnnotatedJField(AnnotatedField afield, JField[] children) {
		this.subFields = children;
		this.priority = afield.getPriority();
		this.name = afield.getName();
		this.nicname = afield.getNicname();
		afield.getDisplay();
		afield.getUnits();
		this.style = afield.getStyle();

		value = afield.getRuntime().getFunctionMap().get(Field.Property.VALUE);
		offset = afield.getRuntime().getFunctionMap().get(Field.Property.OFFSET);
		length = afield.getRuntime().getFunctionMap().get(Field.Property.LENGTH);
		display = afield.getRuntime().getFunctionMap().get(Field.Property.DISPLAY);
		description =
				afield.getRuntime().getFunctionMap().get(Field.Property.DESCRIPTION);
		mask = afield.getRuntime().getFunctionMap().get(Field.Property.MASK);
		check = afield.getRuntime().getFunctionMap().get(Field.Property.CHECK);
		units = afield.getRuntime().getFunctionMap().get(Field.Property.UNITS);

		for (JField f : subFields) {
			f.setParent(this);
		}
	}

	/**
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getSubFields()
	 */
	@Override
	public JField[] getSubFields() {
		return subFields;
	}

	/**
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getName()
	 */
	@Override
	public String getName() {
		return this.name;
	}

	/**
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getNicname()
	 */
	@Override
	public String getNicname() {
		return nicname;
	}

	/**
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getPriority()
	 */
	@Override
	public Priority getPriority() {
		return priority;
	}

	/**
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getStyle()
	 */
	@Override
	public Style getStyle() {
		return style;
	}

	/**
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#hasSubFields()
	 */
	@Override
	public boolean hasSubFields() {
		return subFields.length != 0;
	}

	/**
	 * Sets the style.
	 * 
	 * @param style
	 *          the new style
	 */
	@Override
	public void setStyle(Style style) {
		this.style = style;
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getUnits(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public String getUnits(JHeader header) {
		return units.stringMethod(header, name);
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#hasField(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public boolean hasField(JHeader header) {
		return check.booleanMethod(header, name);
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getDisplay(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public String getDisplay(JHeader header) {
		return display.stringMethod(header, name);
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getLength(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public int getLength(JHeader header) {
		return length.intMethod(header, name);
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getMask(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public long getMask(JHeader header) {
		return mask.longMethod(header, name);
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getOffset(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public int getOffset(JHeader header) {
		return offset.intMethod(header, name);
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getValueDescription(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public String getValueDescription(JHeader header) {
		return description.stringMethod(header, name);
	}

	/**
	 * @param <T>
	 * @param c
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getValue(java.lang.Class,
	 *      org.jnetpcap.packet.JHeader)
	 */
	@Override
	@SuppressWarnings("unchecked")
	public <T> T getValue(Class<T> c, JHeader header) {
		return (T) value.objectMethod(header, name);
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#getValue(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public Object getValue(JHeader header) {
		return value.objectMethod(header, name);
	}

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.IField#longValue(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public long longValue(JHeader header) {
		Object o = getValue(header);
		if (o instanceof Number) {
			return ((Number) o).longValue();
		} else if (o instanceof Boolean) {
			return ((Boolean) o).booleanValue() ? 1L : 0L;
		} else if (o instanceof String) {
			return Long.parseLong(o.toString());
		} else {
			throw new IllegalStateException("unknown format encountered");
		}
	}

}
