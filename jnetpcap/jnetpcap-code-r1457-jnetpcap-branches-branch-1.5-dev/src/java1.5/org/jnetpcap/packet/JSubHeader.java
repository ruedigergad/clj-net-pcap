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

import org.jnetpcap.packet.structure.JField;

// TODO: Auto-generated Javadoc
/**
 * The Class JSubHeader.
 * 
 * @param <T>
 *          the generic type
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JSubHeader<T extends JHeader>
    extends JHeader {

	/** The length. */
	private int length;

	/** The offset. */
	private int offset;

	/** The parent. */
	private JHeader parent;

	/**
	 * Instantiates a new j sub header.
	 */
	public JSubHeader() {
		super();
	}

	/**
	 * Instantiates a new j sub header.
	 * 
	 * @param id
	 *          the id
	 * @param fields
	 *          the fields
	 * @param name
	 *          the name
	 * @param nicname
	 *          the nicname
	 */
	public JSubHeader(int id, JField[] fields, String name, String nicname) {
		super(id, fields, name, nicname);
	}

	/**
	 * Instantiates a new j sub header.
	 * 
	 * @param id
	 *          the id
	 * @param fields
	 *          the fields
	 * @param name
	 *          the name
	 */
	public JSubHeader(int id, JField[] fields, String name) {
		super(id, fields, name);
	}

	/**
	 * Instantiates a new j sub header.
	 * 
	 * @param id
	 *          the id
	 * @param name
	 *          the name
	 * @param nicname
	 *          the nicname
	 */
	public JSubHeader(int id, String name, String nicname) {
		super(id, name, nicname);
	}

	/**
	 * Instantiates a new j sub header.
	 * 
	 * @param id
	 *          the id
	 * @param name
	 *          the name
	 */
	public JSubHeader(int id, String name) {
		super(id, name);
	}

	/**
	 * Instantiates a new j sub header.
	 * 
	 * @param state
	 *          the state
	 * @param fields
	 *          the fields
	 * @param name
	 *          the name
	 * @param nicname
	 *          the nicname
	 */
	public JSubHeader(State state, JField[] fields, String name, String nicname) {
		super(state, fields, name, nicname);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeader#getLength()
	 */
	/**
	 * Gets the length.
	 * 
	 * @return the length
	 * @see org.jnetpcap.packet.JHeader#getLength()
	 */
	@Override
	public int getLength() {
		return length;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeader#getOffset()
	 */
	/**
	 * Gets the offset.
	 * 
	 * @return the offset
	 * @see org.jnetpcap.packet.JHeader#getOffset()
	 */
	@Override
	public int getOffset() {
		return offset;
	}

	/**
	 * Sets the offset.
	 * 
	 * @param offset
	 *          the new offset
	 */
	public void setOffset(int offset) {
		this.offset = offset;
	}

	/**
	 * Sets the length.
	 * 
	 * @param length
	 *          the new length
	 */
	public void setLength(int length) {
		this.length = length;
	}

	/**
	 * Sets the parent.
	 * 
	 * @param parent
	 *          the new parent
	 */
	public void setParent(JHeader parent) {
		this.parent = parent;
	}

	/**
	 * Gets the parent.
	 * 
	 * @return the parent
	 * @see org.jnetpcap.packet.JHeader#getParent()
	 */
	public JHeader getParent() {
		return this.parent;
	}

}
