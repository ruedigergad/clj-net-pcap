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
package org.jnetpcap.protocol.network;

import org.jnetpcap.packet.annotate.Field;

// TODO: Auto-generated Javadoc
/**
 * Routing Information Protocol version 2. Extends the basic Rip1 header by
 * supplying an extends EntryV1 definition. Both v1 and v2 entries are forward
 * and backward compatible, with Rip1 reader ignoring the rip2 specific fields.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @see Rip1
 */
public abstract class Rip2
    extends
    Rip1 {

	/** The routing table. */
	private EntryV2[] routingTable;

	/**
	 * Gets the routing table.
	 * 
	 * @return an array of routing table entries
	 */
	@Field(offset = 4 * 8)
	public EntryV2[] routingTable() {
		if (this.routingTable == null) {
			decodeRoutingTable();
		}

		return this.routingTable;
	}

	/**
	 * Do the actual decoding of the routing table.
	 */
	private void decodeRoutingTable() {

		this.routingTable = new EntryV2[count];

		for (int i = 0; i < count; i++) {
			final EntryV2 e = new EntryV2();
			this.routingTable[i] = e;

			e.peer(this, 4 + i * 20, 20);
		}
	}

	/**
	 * Rip2 routing table entry definition. Overrides V1 definition and adds V2
	 * specific fields. V2 fields are unused but reserved present in V1 structure.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class EntryV2
	    extends
	    EntryV1 {

		/**
		 * Tag.
		 * 
		 * @return the int
		 */
		@Field(offset = 2 * 8, length = 16)
		public int tag() {
			return super.getUShort(2);
		}

		/**
		 * Subnet.
		 * 
		 * @return the byte[]
		 */
		@Field(offset = 8 * 8, length = 32)
		public byte[] subnet() {
			return super.getByteArray(8, 4);
		}

		/**
		 * Next hop.
		 * 
		 * @return the byte[]
		 */
		@Field(offset = 12 * 8, length = 32)
		public byte[] nextHop() {
			return super.getByteArray(12, 4);
		}
	}
}
