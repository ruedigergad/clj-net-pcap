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

import org.jnetpcap.nio.JBuffer;

// TODO: Auto-generated Javadoc
/**
 * Various data manipulation utilities.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class DataUtils {
	
	/**
	 * Returns the difference between b1 and b2. b1 is subtracted from b2.
	 * 
	 * @param b1
	 *          the b1
	 * @param b2
	 *          the b2
	 * @return array containing the different between b1 and b2
	 */
	public static byte[] diff(final JBuffer b1, final JBuffer b2) {
		return diff(b1.getByteArray(0, b1.size()), b2.getByteArray(0, b2.size()));
	}

	
	/**
	 * Returns the difference between b1 and b2. b1 is subtracted from b2.
	 * 
	 * @param b1
	 *          the b1
	 * @param b2
	 *          the b2
	 * @return array containing the different between b1 and b2
	 */
	public static byte[] diff(final byte[] b1, final JBuffer b2) {
		return diff(b1, b2.getByteArray(0, b2.size()));
	}

	/**
	 * Returns the difference between b1 and b2. b1 is subtracted from b2.
	 * 
	 * @param b1
	 *          the b1
	 * @param b2
	 *          the b2
	 * @return array containing the different between b1 and b2
	 */
	public static byte[] diff(final byte[] b1, final byte[] b2) {

		final int max = (b1.length > b2.length) ? b1.length : b2.length;
		final byte[] b = new byte[max];

		for (int i = 0; i < max; i++) {

			final byte t1 = (i < b1.length) ? b1[i] : 0;
			final byte t2 = (i < b2.length) ? b2[i] : 0;

			b[i] = (byte) (t2 - t1);
		}
		
		return b;
	}
}
