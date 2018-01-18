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
 * A dispatchable packet hadler. The handler receives fully decoded packets from
 * libpcap library.
 * 
 * @param <T>
 *          the generic type
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JPacketHandler<T> {

	/**
	 * Callback function called on by libpcap and jNetPcap scanner once a new
	 * packet arrives and has passed the set BPF filter. The packet object
	 * dispatched is not allocated on a per call basis, but is shared between
	 * every call made. At the time the pcap dispatch or loop is established a
	 * freshly allocated packet is used to peer with received packet buffers from
	 * libpcap, scanned then dispatched to this method for the user to process.
	 * The packet memory and state is not persistent between calls. If a more
	 * persistent state is need it must be copied outof the supplied packet into a
	 * more permanent packet.
	 * 
	 * <pre>
	 * public void nextPacket(JPacket packet, T user) {
	 * 	JPacket permanentPacket = new JPacket(packet);// creates a permanent packet
	 * }
	 * </pre>
	 * 
	 * @param packet
	 *          a non persistent between invokations decoded packet
	 * @param user
	 *          user supplied object of type <T>
	 */
	public void nextPacket(JPacket packet, T user);

}
