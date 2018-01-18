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

import java.util.Arrays;
import java.util.Comparator;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * A field within a header. Field objects are used to describe the structure of
 * a header to a formatter. The formatter iterates through all the fields it
 * receives from a header and using formatting information stored in these
 * fields, creates formatted output.
 * <p>
 * There are 2 types of main fields, <code>AnnotatedJField</code> and
 * <code>DefaultFField</code>. The <code>AnnotatedJField</code> is initialized
 * by extracting information from header definition which uses annotations to
 * mark fields and special dynamic properties of fields.
 * </p>
 * <p>
 * The <code>DefaultJField</code> class is more stand-alone field, which stores
 * information locally and all field properties have to be supplied by its user.
 * This type of field is used for maximum flexibility at the expense of easy
 * since all of the data has to be supplied to it at runtime.
 * </p>
 * 
 * @author Sly Technologies, Inc.
 * @see Field
 */
public abstract class JField {

	/**
	 * The Class JFieldComp.
	 */
	private static class JFieldComp implements Comparator<JField> {

		/** The ascending. */
		private boolean ascending = true;

		/** The header. */
		private JHeader header;
		
		public JFieldComp() {
			
		}

		/**
		 * Compare.
		 * 
		 * @param o1
		 *            the o1
		 * @param o2
		 *            the o2
		 * @return the int
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		public int compare(JField o1, JField o2) {
			if (ascending) {
				return o1.getOffset(header) - o2.getOffset(header);
			} else {
				return o2.getOffset(header) - o1.getOffset(header);
			}
		}

		/**
		 * Sets the ascending.
		 * 
		 * @param ascending
		 *            the new ascending
		 */
		public void setAscending(boolean ascending) {
			this.ascending = ascending;
		}

		/**
		 * Sets the header.
		 * 
		 * @param header
		 *            the new header
		 */
		public void setHeader(JHeader header) {
			this.header = header;
		}

	}

	/** The Constant SORT_BY_OFFSET. */
	private final static ThreadLocal<JFieldComp> SORT_BY_OFFSET =
			new ThreadLocal<JFieldComp>() {

				@Override
				protected JFieldComp initialValue() {
					return new JFieldComp();
				}
		
	};

	/**
	 * Sort field by offset.
	 * 
	 * @param fields
	 *            the fields
	 * @param header
	 *            the header
	 * @param ascending
	 *            the ascending
	 */
	public static void sortFieldByOffset(JField[] fields, JHeader header,
			boolean ascending) {

		JFieldComp byOffset = SORT_BY_OFFSET.get();

		byOffset.setAscending(ascending);
		byOffset.setHeader(header);
		Arrays.sort(fields, byOffset);
	}

	/** The parent. */
	private JField parent;

	public JField() {
		this.parent = null;
	}

	public JField(JField parent) {
		this.parent = parent;
	}

	/**
	 * Gets the display.
	 * 
	 * @param header
	 *            the header
	 * @return the display
	 */
	public abstract String getDisplay(JHeader header);

	/**
	 * Gets the length.
	 * 
	 * @param header
	 *            the header
	 * @return the length
	 */
	public abstract int getLength(JHeader header);

	/**
	 * Gets the mask.
	 * 
	 * @param header
	 *            the header
	 * @return the mask
	 */
	public abstract long getMask(JHeader header);

	/**
	 * Gets the name.
	 * 
	 * @return the name
	 */
	public abstract String getName();

	/**
	 * Gets the nicname.
	 * 
	 * @return the nicname
	 */
	public abstract String getNicname();

	/**
	 * Gets the offset.
	 * 
	 * @param header
	 *            the header
	 * @return the offset
	 */
	public abstract int getOffset(JHeader header);

	/**
	 * Gets the parent.
	 * 
	 * @return the parent
	 */
	public JField getParent() {
		return parent;
	}

	/**
	 * Gets the priority.
	 * 
	 * @return the priority
	 */
	public abstract Priority getPriority();

	/**
	 * Gets the style.
	 * 
	 * @return the style
	 */
	public abstract Style getStyle();

	/**
	 * Gets the sub fields.
	 * 
	 * @return the sub fields
	 */
	public abstract JField[] getSubFields();

	/**
	 * Gets the units.
	 * 
	 * @param header
	 *            the header
	 * @return the units
	 */
	public abstract String getUnits(JHeader header);

	/**
	 * Gets the value.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param c
	 *            the c
	 * @param header
	 *            the header
	 * @return the value
	 */
	public abstract <T> T getValue(Class<T> c, JHeader header);

	/**
	 * Gets the value.
	 * 
	 * @param header
	 *            the header
	 * @return the value
	 */
	public abstract Object getValue(JHeader header);

	/**
	 * Gets the value description.
	 * 
	 * @param header
	 *            the header
	 * @return the value description
	 */
	public abstract String getValueDescription(JHeader header);

	/**
	 * Checks for field.
	 * 
	 * @param header
	 *            the header
	 * @return true, if successful
	 */
	public abstract boolean hasField(JHeader header);

	/**
	 * Checks for sub fields.
	 * 
	 * @return true, if successful
	 */
	public abstract boolean hasSubFields();

	/**
	 * Long value.
	 * 
	 * @param header
	 *            the header
	 * @return the long
	 */
	public abstract long longValue(JHeader header);

	/**
	 * Sets the parent of this sub-field and only when this field is a
	 * sub-field.
	 * 
	 * @param parent
	 *            the parent to set
	 */
	public final void setParent(JField parent) {
		this.parent = parent;
	}

	/**
	 * Sets the style.
	 * 
	 * @param style
	 *            the new style
	 */
	public abstract void setStyle(Style style);

}
