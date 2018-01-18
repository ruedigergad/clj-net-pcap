/**
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

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.DisposableReference;

// TODO: Auto-generated Javadoc
/**
 * The Class NativeLibraryReference.
 * 
 * @author Sly Technologies, Inc.
 */
@Library(jni = Pcap.LIBRARY)
public class NativeLibraryReference extends DisposableReference {

	/** The address. */
	private long address;

	/**
	 * Instantiates a new native library reference.
	 * 
	 * @param referant
	 *          the referant
	 * @param address
	 *          the address
	 */
	public NativeLibraryReference(Object referant, long address) {
		super(referant);
		this.address = address;
	}

	/**
	 * Dispose.
	 * 
	 * @see org.jnetpcap.nio.DisposableReference#dispose()
	 */
	@Override
	public void dispose() {
		if (address != 0) {
			dlclose(address);
			address = 0;
		}

		super.dispose();
	}

	/**
	 * Dlclose.
	 * 
	 * @param address
	 *          the address
	 */
	private static native void dlclose(long address);
}
