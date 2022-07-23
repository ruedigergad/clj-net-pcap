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
package com.slytechs.library;


/**
 * A symbol that is part of a library.
 * 
 * @author Sly Technologies, Inc.
 * 
 */
public class NativeSymbol {

	/** The address. */
	public final long address;

	/** The native name. */
	public final String nativeName;

	public final String libName;

	/**
	 * Instantiates a new native symbol.
	 * 
	 * @param name
	 *          the name
	 * @param address
	 *          the address
	 */
	NativeSymbol(String name, long address, String libName) {
		this.nativeName = name;
		this.address = address;
		this.libName = libName;
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (libName == null) {
			return nativeName + "!NOT_FOUND";
		} else {
			return libName + "::" + nativeName + "@0x" + Long.toHexString(address);
		}
	}

	/**
	 * Checks if is found.
	 * 
	 * @return true, if is found
	 */
	public boolean isFound() {
		return address != 0L;
	}
}
