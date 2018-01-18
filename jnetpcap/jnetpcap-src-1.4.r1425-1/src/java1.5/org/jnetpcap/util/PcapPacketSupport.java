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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

// TODO: Auto-generated Javadoc
/**
 * A utility class that dispatches a PcapPacket to any number of listeners. The
 * packet is simply forwarded to any listeners as is.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapPacketSupport implements PcapPacketHandler<Object>{

	/**
	 * The Class Entry.
	 */
	private static class Entry {
		
		/** The handler. */
		public PcapPacketHandler<Object> handler;

		/** The user. */
		public Object user;

		/**
		 * Instantiates a new entry.
		 * 
		 * @param handler
		 *          the handler
		 * @param user
		 *          the user
		 */
		@SuppressWarnings("unchecked")
		public Entry(PcapPacketHandler<?> handler, Object user) {
			this.handler = (PcapPacketHandler<Object>) handler;
			this.user = user;
		}

	}

	/** The listeners. */
	private List<Entry> listeners = new ArrayList<Entry>();

	/** The listeners array. */
	private Entry[] listenersArray = null;

	/**
	 * Adds the.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param o
	 *          the o
	 * @param user
	 *          the user
	 * @return true, if successful
	 */
	public <T> boolean add(PcapPacketHandler<T> o, T user) {
		listenersArray = null; // reset

		return this.listeners.add(new Entry(o, user));
	}

	/**
	 * Removes the.
	 * 
	 * @param o
	 *          the o
	 * @return true, if successful
	 */
	public boolean remove(PcapPacketHandler<?> o) {
		listenersArray = null;

		for (Iterator<Entry> i = listeners.iterator(); i.hasNext();) {
			Entry e = i.next();
			if (o == e.handler) {
				i.remove();

				listenersArray = null; // reset
				return true;
			}
		}

		return false;
	}

	/**
	 * Fire next packet.
	 * 
	 * @param packet
	 *          the packet
	 */
	public void fireNextPacket(PcapPacket packet) {
		if (listenersArray == null) {
			listenersArray = listeners.toArray(new Entry[listeners.size()]);
		}

		/*
		 * More efficient to loop through array than iterator
		 */
		for (Entry e : listenersArray) {
			e.handler.nextPacket(packet, e.user);
		}
	}

	/* (non-Javadoc)
   * @see org.jnetpcap.packet.PcapPacketHandler#nextPacket(org.jnetpcap.packet.PcapPacket, java.lang.Object)
   */
  /**
	 * Next packet.
	 * 
	 * @param packet
	 *          the packet
	 * @param user
	 *          the user
	 * @see org.jnetpcap.packet.PcapPacketHandler#nextPacket(org.jnetpcap.packet.PcapPacket,
	 *      java.lang.Object)
	 */
	public void nextPacket(PcapPacket packet, Object user) {
  	fireNextPacket(packet);
  }

}
