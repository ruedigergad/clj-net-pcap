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

import java.nio.ByteBuffer;

import org.jnetpcap.nio.JBuffer;

// TODO: Auto-generated Javadoc
/**
 * Interface which provides access to payload portion of the packet data. When
 * considered from a header's perspective, each header has a raw payload
 * portion, which may be other headers. The remaining, undecoded data at the end
 * of the packet is simply payload of the last header.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JPayloadAccessor {
	/**
	 * Retrieves the playload data portion of the packet right after the current
	 * header.
	 * 
	 * @return newly allocated byte array containing copy of the contents of the
	 *         header's payload from the packet.
	 */
	public byte[] getPayload();

	/**
	 * Copies the payload data portion of the packet right after the current
	 * header to user supplied buffer.
	 * 
	 * @param buffer
	 *          buffer where the data will be written to
	 * @return the same buffer that was passed in
	 */
	public byte[] transferPayloadTo(byte[] buffer);

	/**
	 * Peers, without copy, the user supplied buffer with payload data portion of
	 * the packet right after the current header.
	 * 
	 * @param buffer
	 *          buffer to peer the data with
	 * @return the same buffer that was passed in
	 */
	public JBuffer peerPayloadTo(JBuffer buffer);

	/**
	 * Copies into the user supplied buffer, the payload data portion of the
	 * packet right after the current header.
	 * 
	 * @param buffer
	 *          buffer to copy the data to
	 * @return the same buffer that was passed in
	 */
	public JBuffer transferPayloadTo(JBuffer buffer);

	/**
	 * Copies into the user supplied buffer, the payload data portion of the
	 * packet right after the current header. The copy will start at the current
	 * ByteBuffer position property.
	 * 
	 * @param buffer
	 *          buffer to copy the data to
	 * @return the same buffer that was passed in
	 */
	public ByteBuffer transferPayloadTo(ByteBuffer buffer);

}
