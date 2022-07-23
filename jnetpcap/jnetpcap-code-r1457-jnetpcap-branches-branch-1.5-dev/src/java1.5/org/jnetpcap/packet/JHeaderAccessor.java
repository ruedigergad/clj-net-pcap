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

// TODO: Auto-generated Javadoc
/**
 * Accessor to get a structured header from underlying buffer.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JHeaderAccessor {

	/**
	 * Peers the supplied header with the native header state structure and packet
	 * data buffer.
	 * 
	 * @param <T>
	 *          name of the header
	 * @param header
	 *          instance of a header object
	 * @return the supplied instance of the header
	 */
	public <T extends JHeader> T getHeader(T header);

	/**
	 * Peers the supplied header with the native header state structure and packet
	 * data buffer. This method allows retrieval of a specific instance of a
	 * header if more than one instance has been found.
	 * 
	 * @param <T>
	 *          name of the header
	 * @param header
	 *          instance of a header object
	 * @param instance
	 *          instance number of the header since more than one header of the
	 *          same type can exist in the same packet buffer
	 * @return the supplied instance of the header
	 */
	public <T extends JHeader> T getHeader(T header, int instance);

	/**
	 * Peers a header with specific index, not the numerical header ID assigned by
	 * JRegistry, of a header.
	 * 
	 * @param <T>
	 *          name of the header
	 * @param index
	 *          index into the header array the scanner has found
	 * @param header
	 *          instance of a header object
	 * @return the supplied header
	 */
	public <T extends JHeader> T getHeaderByIndex(int index, T header);

	/**
	 * Gets number of headers found within the packet header. The last header may
	 * or may not be the builtin Payload header
	 * 
	 * @return number of headers present
	 */
	public int getHeaderCount();

	/**
	 * Gets the numerical ID of the header at specified index into header array as
	 * found by the packet scanner.
	 * 
	 * @param index
	 *          index into the header array
	 * @return numerical ID of the header found at the specific index
	 */
	public int getHeaderIdByIndex(int index);

	/**
	 * Gets number of headers with the same numerical ID as assigned by JRegistry
	 * within the same packet. For example Ip4 in ip4 packet would contain 2
	 * instances of Ip4 header.
	 * 
	 * @param id
	 *          numerical ID of the header to search for
	 * @return number of headers of the same type in the packet
	 */
	public int getHeaderInstanceCount(int id);

	/**
	 * Checks if header with specified numerical ID exists within the decoded
	 * packet.
	 * 
	 * @param id
	 *          protocol header ID as assigned by JRegistry
	 * @return true header exists, otherwise false
	 */
	public boolean hasHeader(int id);

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet.
	 * 
	 * @param id
	 *          protocol header ID as assigned by JRegistry
	 * @param instance
	 *          instance number of the specific header within the packet
	 * @return true header exists, otherwise false
	 */
	public boolean hasHeader(int id, int instance);

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet and if found peers the supplied header with the
	 * located header within the decoded packet. This method executes as hasHeader
	 * followed by getHeader if found more efficiently.
	 * 
	 * @param <T>
	 *          name of the header type
	 * @param header
	 *          protocol header object instance
	 * @return true header exists, otherwise false
	 */
	public <T extends JHeader> boolean hasHeader(T header);

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet and if found peers the supplied header with the
	 * located header within the decoded packet. This method executes as hasHeader
	 * followed by getHeader if found more efficiently.
	 * 
	 * @param <T>
	 *          name of the header type
	 * @param header
	 *          protocol header object instance
	 * @param instance
	 *          instance number of the specific header within the packet
	 * @return true header exists, otherwise false
	 */
	public <T extends JHeader> boolean hasHeader(T header, int instance);
}
