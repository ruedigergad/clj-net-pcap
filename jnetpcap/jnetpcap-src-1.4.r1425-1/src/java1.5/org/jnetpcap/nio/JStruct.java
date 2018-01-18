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
package org.jnetpcap.nio;

import java.nio.ByteBuffer;

// TODO: Auto-generated Javadoc
/**
 * Base class for peered pure structure classes. This class purposely does not
 * extend JBuffer to allow structure fields to be read out generically as that
 * is not portable accross platforms and architectures. Most structures are
 * written specifically for local machine architecture and OS, unlike network
 * protocols which can be usually read by use of generic <code>JBuffer</code>.
 * Therefore as a general requirement each JStruct has to implement its own
 * native methods to read and write fields into the structure.
 * <p>
 * As a convention, each subclass of JStruct implements a static method
 * <code>sizeof()</code> which returns the length of the structure, if the
 * structure is static in length. If not, then no requirement to implement the
 * static method <code>sizeof()</code> exists.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JStruct
    extends
    JMemory {

	/** Name of the native structure. */
	private final String structName;

	/**
	 * Creates a new structure object.
	 * 
	 * @param structName
	 *          name of the native structure
	 * @param type
	 *          memory model
	 */
	public JStruct(String structName, Type type) {
		super(type);
		this.structName = structName;
	}

	/**
	 * Creates a new structure object peered with the supplied object.
	 * 
	 * @param structName
	 *          name of the native structure
	 * @param peer
	 *          buffer to peer with
	 */
	public JStruct(String structName, ByteBuffer peer) {
		super(peer);
		this.structName = structName;
	}

	/**
	 * Creates a new structure object of specified size.
	 * 
	 * @param structName
	 *          name of the native structure
	 * @param size
	 *          size in bytes for this new structure object
	 */
	public JStruct(String structName, int size) {
		super(size);
		this.structName = structName;
	}

	/**
	 * Creates a new structure object.
	 * 
	 * @param structName
	 *          name of the native structure
	 * @param peer
	 *          memory to peer with
	 */
	public JStruct(String structName, JMemory peer) {
		super(peer);
		this.structName = structName;
	}

	/**
	 * Gets the name of the native structure
	 * 
	 * @return name of the structure
	 */
	public final String getStructName() {
		return this.structName;
	}

	/**
	 * Debug information.
	 * 
	 * @return debug info
	 */
	public String toString() {
		return "struct " + structName;
	}
}
