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

import java.beans.PropertyChangeEvent;

// TODO: Auto-generated Javadoc
/**
 * An event object and event related utilities.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JEvent {

	/**
	 * Int value.
	 * 
	 * @param evt
	 *          the evt
	 * @return the int
	 */
	public static int intValue(PropertyChangeEvent evt) {
		return Integer.parseInt((String) evt.getNewValue());
	}

	/**
	 * Long value.
	 * 
	 * @param evt
	 *          the evt
	 * @return the long
	 */
	public static long longValue(PropertyChangeEvent evt) {
		return Long.parseLong((String) evt.getNewValue());
	}

	/**
	 * Boolean value.
	 * 
	 * @param evt
	 *          the evt
	 * @return true, if successful
	 */
	public static boolean booleanValue(PropertyChangeEvent evt) {
		return Boolean.parseBoolean((String) evt.getNewValue());
	}

	/**
	 * String value.
	 * 
	 * @param evt
	 *          the evt
	 * @return the string
	 */
	public static String stringValue(PropertyChangeEvent evt) {
		return (String) evt.getNewValue();
	}

}
