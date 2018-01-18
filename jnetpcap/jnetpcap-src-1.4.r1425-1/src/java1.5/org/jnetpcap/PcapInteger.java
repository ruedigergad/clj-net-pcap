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
package org.jnetpcap;

import org.jnetpcap.nio.JNumber;

// TODO: Auto-generated Javadoc
/**
 * An 32-bit integer reference that can be used to pass into pcap methods that
 * require an integer pointer to be set as a return value. The object is not
 * peered with any native structures, but is set using special JNI priviledges.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @deprecated replaced by JNumber
 * @see JNumber
 */
public final class PcapInteger {

	/** Modified from JNI methods. */
	private volatile int value;

	/**
	 * Initializes the object with int value.
	 * 
	 * @param value
	 *          value to initialize the object with
	 */
	public PcapInteger(int value) {
		this.value = value;
	}

	/**
	 * Creates an 0 initialized integer object.
	 */
	public PcapInteger() {
		this.value = 0;
	}

	/**
	 * Gets the current value
	 * 
	 * @return the value
	 */
	public final int getValue() {
		return this.value;
	}

	/**
	 * Sets a new value
	 * 
	 * @param value
	 *          the value to set
	 */
	public final void setValue(int value) {
		this.value = value;
	}

	/**
	 * Returns string representation of the integer.
	 * 
	 * @return integer as a string
	 */
	@Override
  public String toString() {
		return Integer.toString(value);
	}
}
