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

// TODO: Auto-generated Javadoc
/**
 * A handler, listener or call back inteface that gets notified when a new
 * packet has been captured.
 * 
 * @param <T>
 *          user object type
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface ByteBufferHandler<T> {

	/**
	 * Callback method that will called by libpcap when a new packet is captured.
	 * 
	 * @param header
	 *          pcap capture header
	 * @param buffer
	 *          Buffer containing packet data. The new ByteBuffer object is
	 *          allocated per call for the peering, the data is not copied but
	 *          referenced.
	 * @param user
	 *          user supplied object
	 */
	public void nextPacket(PcapHeader header, ByteBuffer buffer, T user);
}
