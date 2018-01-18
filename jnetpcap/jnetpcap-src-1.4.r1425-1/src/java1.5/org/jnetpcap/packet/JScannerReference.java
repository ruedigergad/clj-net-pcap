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

import org.jnetpcap.nio.JMemoryReference;

// TODO: Auto-generated Javadoc
/**
 * The Class JScannerReference.
 * 
 * @author markbe
 */
public class JScannerReference extends JMemoryReference {

	/**
	 * Instantiates a new j scanner reference.
	 * 
	 * @param referant
	 *          the referant
	 * @param address
	 *          the address
	 * @param size
	 *          the size
	 */
	public JScannerReference(Object referant, long address, long size) {
		super(referant, address, size);
	}

	/**
	 * Clean up the scanner_t structure and release any held resources. For one
	 * all the JHeaderScanners that are kept as global references need to be
	 * released.
	 * 
	 * @param size
	 *          the size
	 */
	protected native void disposeNative(long size);

}
