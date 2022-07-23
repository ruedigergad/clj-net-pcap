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

import java.nio.ByteOrder;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.protocol.lan.Ethernet;

// TODO: Auto-generated Javadoc
/**
 * The Class JPcapRecordBuffer.
 */
public class JPcapRecordBuffer extends JBuffer implements JPcapRecordIterable {

	/**
	 * The Class Iterator.
	 */
	public class Iterator implements
			java.util.Iterator<JPcapRecordBuffer.Record> {

		/** The offset. */
		private int offset = start;

		/** The index. */
		private int index = 0;

		/** The PCA p_ heade r_ sizeof. */
		final int PCAP_HEADER_SIZEOF = PcapHeader.sizeof();

		/**
		 * Gets the packet record count.
		 * 
		 * @return the packet record count
		 */
		public long getPacketRecordCount() {
			return count;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Iterator#hasNext()
		 */
		public boolean hasNext() {
			return index < count;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Iterator#next()
		 */
		public JPcapRecordBuffer.Record next() {
			return records[index++];
		}

		/**
		 * Next.
		 * 
		 * @param header
		 *            the header
		 * @param packet
		 *            the packet
		 */
		public void next(PcapHeader header, JBuffer packet) {
			// System.out.printf("next():: offset=%d index=%d size=%d count=%d%n",
			// offset,
			// index,
			// size(),
			// count);
			// System.out.flush();

			offset += header.peerTo(JPcapRecordBuffer.this, offset);
			// offset += PCAP_HEADER_SIZEOF;

			offset += packet.peer(JPcapRecordBuffer.this, offset,
					header.caplen());
			// offset += header.caplen();
			index++;

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Iterator#remove()
		 */
		public void remove() {
			throw new UnsupportedOperationException(
					"optional method not implemented");
		}

		/**
		 * Reset.
		 */
		public void reset() {
			offset = start;
			index = 0;
		}

	}

	/**
	 * The Class Record.
	 */
	public static class Record {

		/** The header. */
		public PcapHeader header;

		/** The packet. */
		public JBuffer packet;
	}

	/** The start. */
	private final int start = 4;

	/** The limit. */
	private int limit;

	/** The position. */
	private int position = start;

	/** The capacity. */
	private final int capacity;

	/** The count. */
	private int count = 0;

	/** The records. */
	private Record[] records;

	/** The header. */
	final PcapHeader header = new PcapHeader(JMemory.POINTER);

	/** The pkt_buf. */
	final JBuffer pkt_buf = new JBuffer(JMemory.POINTER);

	/** The packet. */
	final PcapPacket packet = new PcapPacket(JMemory.POINTER);

	/**
	 * Instantiates a new j pcap record buffer.
	 * 
	 * @param size
	 *            the size
	 */
	public JPcapRecordBuffer(int size) {
		super(size);
		this.capacity = size;
		this.limit = capacity;

		this.order(ByteOrder.nativeOrder());
	}

	/**
	 * Append.
	 * 
	 * @param header
	 *            the header
	 * @param packet
	 *            the packet
	 */
	public void append(PcapHeader header, JBuffer packet) {
		header.transferTo(this, position);
		position += PcapHeader.sizeof();

		packet.transferTo(this, 0, packet.size(), position);
		position += packet.size();

		count++;
	}

	/**
	 * Close.
	 */
	public void close() {
		limit = position;
		position = start;

		this.setInt(0, count);

		JBuffer b = new JBuffer(limit);
		b.order(ByteOrder.nativeOrder());
		this.transferTo(b, 0, limit, 0);

		// Resize to smaller
		setSize(limit);

		records = new Record[count];

		Iterator it = iterator();
		for (int i = 0; i < count && it.hasNext(); i++) {
			records[i] = new Record();
			records[i].header = new PcapHeader(JMemory.POINTER);
			records[i].packet = new JBuffer(JMemory.POINTER);

			it.next(records[i].header, records[i].packet);
		}
	}

	public <T> long dispatchToJBuffeHandler(JBufferHandler<T> handler, T user) {

		for (Record record : this) {
			handler.nextPacket(record.header, record.packet, user);
		}

		// final JPcapRecordBuffer.Iterator i = buffer.iterator();
		// while (i.hasNext()) {
		// i.next(header, pkt_buf);
		// handler.nextPacket(header, pkt_buf, user);
		// }

		return this.getPacketRecordCount();
	}

	public <T> long dispatchToPcapPacketHandler(PcapPacketHandler<T> handler,
			T user) {

		// for (Record record: buffer) {
		// handler.nextPacket(record.header, record.packet, user);
		// }

		for (JPcapRecordBuffer.Record record : this) {

			// final PcapPacket pkt = new PcapPacket(record.header,
			// record.packet);
			packet.transferHeaderAndDataFrom(record.header, record.packet);
			packet.scan(Ethernet.ID);
			handler.nextPacket(packet, user);
		}

		return this.getPacketRecordCount();
	}

	public int getCapacity() {
		return capacity;
	}

	public int getLimit() {
		return limit;
	}

	/**
	 * Gets the packet record count.
	 * 
	 * @return the packet record count
	 */
	public int getPacketRecordCount() {
		return count;
	}

	public int getPosition() {
		return position;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JPcapRecordIterable#iterator()
	 */
	public JPcapRecordBuffer.Iterator iterator() {
		return new JPcapRecordBuffer.Iterator();
	}

	public int remaining() {
		return limit - position;
	}

	public void setLimit(int limit) {
		this.limit = limit;
	}

	/**
	 * Sets the packet record count.
	 * 
	 * @param value
	 *            the new packet record count
	 */
	@SuppressWarnings("unused")
	private void setPacketRecordCount(int value) {
		super.setUInt(0, value);

		count = value;
	}

	public void setPosition(int position) {
		this.position = position;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "packets = " + count;
	}
}
