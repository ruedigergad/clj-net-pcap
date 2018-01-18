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
package org.jnetpcap.newstuff;

import org.jnetpcap.packet.JHeader;

// TODO: Auto-generated Javadoc
/**
 * The Interface JHeaderContainer.
 * 
 * @param <B>
 *          the generic type
 */
public interface JHeaderContainer<B extends JHeader> {
	
	/**
	 * Adds the header.
	 * 
	 * @param id
	 *          the id
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 */
	public void addHeader(int id, int offset, int length);
	
	/**
	 * Checks for header.
	 * 
	 * @param id
	 *          the id
	 * @return true, if successful
	 */
	public boolean hasHeader(int id);
	
	/**
	 * Checks for header.
	 * 
	 * @param id
	 *          the id
	 * @param instance
	 *          the instance
	 * @return true, if successful
	 */
	public boolean hasHeader(int id, int instance);
	
	/**
	 * Gets the header.
	 * 
	 * @param header
	 *          the header
	 * @return the header
	 */
	public B getHeader(B header);
	
	/**
	 * Gets the header.
	 * 
	 * @param header
	 *          the header
	 * @param instance
	 *          the instance
	 * @return the header
	 */
	public B getHeader(B header, int instance);
	
	/**
	 * Gets the header by index.
	 * 
	 * @param header
	 *          the header
	 * @param index
	 *          the index
	 * @return the header by index
	 */
	public JHeader getHeaderByIndex(JHeader header, int index);
	
	/**
	 * Gets the header count.
	 * 
	 * @return the header count
	 */
	public int getHeaderCount();
	
	/**
	 * Checks for header.
	 * 
	 * @param header
	 *          the header
	 * @return true, if successful
	 */
	public boolean hasHeader(B header);
	
	/**
	 * Clear.
	 */
	public void clear();

}
