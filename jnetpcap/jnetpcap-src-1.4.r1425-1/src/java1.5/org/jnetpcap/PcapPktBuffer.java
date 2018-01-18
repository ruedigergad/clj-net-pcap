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
import java.nio.ByteBuffer;

import org.jnetpcap.nio.JBuffer;

// TODO: Auto-generated Javadoc
/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * Class used to pass back a reference to a ByteBuffer containing the packet
 * data. The private field within this class is assigned new value made up of a
 * ByteBuffer reference from JNI call.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @deprecated replaced by JBuffer
 * 
 * @see JBuffer
 */
public class PcapPktBuffer {
	
	/** The buffer. */
	private volatile ByteBuffer buffer;

	/**
	 * Gets the buffer.
	 * 
	 * @return the buffer
	 */
	public final ByteBuffer getBuffer() {
		return this.buffer;
	}

}
