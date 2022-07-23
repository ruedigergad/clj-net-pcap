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

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.format.FormatUtils;

// TODO: Auto-generated Javadoc
/**
 * A heap based packet. This is a heap (native memory) based packet that can be
 * instantiated without having to supply PcapHeader.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JMemoryPacket
    extends
    JPacket {

	/**
	 * A capture header that stores information about the creation of the packet.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class JMemoryHeader implements JCaptureHeader {

		/** The caplen. */
		private int caplen;

		/** The in micros. */
		private long inMicros;

		/** The in millis. */
		private long inMillis;

		/** The in nanos. */
		private long inNanos;

		/** The nanos. */
		private long nanos;

		/** The seconds. */
		private long seconds;

		/** The wirelen. */
		private int wirelen;

		/**
		 * Creates an empty capture header.
		 */
		public JMemoryHeader() {
			this(0, 0, System.currentTimeMillis() / 1000, System.nanoTime());
			
		}

		/**
		 * Creates a capture header with initial values.
		 * 
		 * @param caplen
		 *          captured length
		 * @param wirelen
		 *          wire length
		 * @param seconds
		 *          timestamp in seconds
		 * @param nanos
		 *          nanos fraction of the timestamp
		 */
		public JMemoryHeader(int caplen, int wirelen, long seconds, long nanos) {
			init(caplen, wirelen, nanos, seconds);
		}

		/**
		 * Gets the capture length.
		 * 
		 * @return length in bytes
		 */
		public int caplen() {
			return caplen;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#caplen(int)
		 */
		/**
		 * Caplen.
		 * 
		 * @param caplen
		 *          the caplen
		 * @see org.jnetpcap.JCaptureHeader#caplen(int)
		 */
		public void caplen(int caplen) {
			this.caplen = caplen;
			if (this.wirelen == 0) {
				setWirelen(caplen);
			}
		}

		/**
		 * Gets the wire length.
		 * 
		 * @return length in bytes
		 */
		public final int getWirelen() {
			return this.wirelen;
		}

		/**
		 * Reinitialized the header to new state.
		 * 
		 * @param caplen
		 *          capture length
		 * @param wirelen
		 *          wirelength
		 * @param nanos
		 *          timestamp fraction in nanos
		 * @param seconds
		 *          timestap in seconds
		 */
		public void init(int caplen, int wirelen, long nanos, long seconds) {
			this.caplen = caplen;
			this.wirelen = wirelen;
			this.nanos = nanos;
			this.seconds = seconds;

			initCompound();
		}

		/**
		 * Inits the compound.
		 */
		private void initCompound() {
			this.inMillis = seconds * 1000 + nanos / 1000000;
			this.inMicros = seconds * 1000000 + nanos / 1000;
			this.inNanos = seconds * 1000000000 + nanos;

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#initFrom(org.jnetpcap.JCaptureHeader)
		 */
		/**
		 * Inits the from.
		 * 
		 * @param header
		 *          the header
		 * @see org.jnetpcap.JCaptureHeader#initFrom(org.jnetpcap.JCaptureHeader)
		 */
		public void initFrom(JCaptureHeader header) {
			init(header.caplen(), header.wirelen(), header.nanos(), header.seconds());
		}

		/**
		 * Gets the timestamp fraction in nanos.
		 * 
		 * @return timestamp fraction
		 */
		public long nanos() {
			return nanos;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#nanos(long)
		 */
		/**
		 * Nanos.
		 * 
		 * @param nanos
		 *          the nanos
		 * @see org.jnetpcap.JCaptureHeader#nanos(long)
		 */
		public void nanos(long nanos) {
			this.nanos = nanos;

			initCompound();
		}

		/**
		 * Gets the timestamp in seconds.
		 * 
		 * @return timestamp
		 */
		public long seconds() {
			return seconds;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#seconds(long)
		 */
		/**
		 * Seconds.
		 * 
		 * @param seconds
		 *          the seconds
		 * @see org.jnetpcap.JCaptureHeader#seconds(long)
		 */
		public void seconds(long seconds) {
			this.seconds = seconds;

			initCompound();
		}

		/**
		 * Sets the states wire length.
		 * 
		 * @param wirelen
		 *          length on the packet on the network wire
		 */
		public final void setWirelen(int wirelen) {
			this.wirelen = wirelen;
			
			if (this.caplen == 0) {
				this.caplen = wirelen;
			}
		}

		/**
		 * Gets the timestamp in micro seconds.
		 * 
		 * @return timestamp in micros
		 */
		public long timestampInMicros() {
			return inMicros;
		}

		/**
		 * Gets the timestamp in millis.
		 * 
		 * @return timestamp in millis
		 */
		public long timestampInMillis() {
			return inMillis;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#timestampInNanos()
		 */
		/**
		 * Timestamp in nanos.
		 * 
		 * @return the long
		 * @see org.jnetpcap.JCaptureHeader#timestampInNanos()
		 */
		public long timestampInNanos() {
			return this.inNanos;
		}

		/**
		 * Gets the wire length.
		 * 
		 * @return length of the packet on the network wire
		 */
		public int wirelen() {
			return wirelen;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#wirelen(int)
		 */
		/**
		 * Wirelen.
		 * 
		 * @param wirelen
		 *          the wirelen
		 * @see org.jnetpcap.JCaptureHeader#wirelen(int)
		 */
		public void wirelen(int wirelen) {
			this.wirelen = wirelen;
		}

	}

	/** The header. */
	private final JMemoryHeader header = new JMemoryHeader();

	/**
	 * Initializes the packet's state and data by doing a deep copy of the
	 * contents of the buffer.
	 * 
	 * @param buffer
	 *          buffer containing both state and data in the form
	 * 
	 *          <pre>
	 * +--------------+-------------+
	 * | packet state | packet data |
	 * +--------------+-------------+
	 * </pre>
	 */
	public JMemoryPacket(byte[] buffer) {
		super(Type.POINTER);

		final JBuffer mem = getMemoryBuffer(buffer);
		super.peer(mem);

		header.setWirelen(buffer.length);
	}

	/**
	 * Initializes the packet's state and data by doing a deep copy of the
	 * contents of the buffer.
	 * 
	 * @param buffer
	 *          buffer containing both state and data in the form
	 * 
	 *          <pre>
	 * +--------------+-------------+
	 * | packet state | packet data |
	 * +--------------+-------------+
	 * </pre>
	 * @throws PeeringException
	 *           if there is a problem peering with the buffer
	 */
	public JMemoryPacket(ByteBuffer buffer) throws PeeringException {
		super(Type.POINTER);
		
		final int size = buffer.limit() - buffer.position();

		final JBuffer mem = getMemoryBuffer(size);
		super.peer(mem);
		
		transferFrom(buffer);

		header.setWirelen(size);
	}

	/**
	 * Preallocates a packet with internal buffer of the supplied size.
	 * 
	 * @param size
	 *          number of bytes to pre allocate
	 */
	public JMemoryPacket(int size) {
		super(size, 0);

		header.setWirelen(size);
		
		/**
		 * Bug #2878768	JMemoryPacket(int) constructor doesn't work
		 */
		super.peer(super.memory);
	}

	/**
	 * Creates a new fully decoded packet from data provides in the buffer. The
	 * buffer contains raw packet data. The packet is peered with the buffer,
	 * allocating new memory if neccessary, and scanned using internal scanner.
	 * 
	 * @param id
	 *          numerical id of first protocol (DLT)
	 * @param buffer
	 *          buffer containing raw packet data
	 */
	public JMemoryPacket(int id, byte[] buffer) {
		this(buffer);

		scan(id);
	}

	/**
	 * Initializes the packet's state and data by doing a deep copy of the
	 * contents of the buffer. This constructor also performs a scan of the
	 * packet.
	 * 
	 * @param id
	 *          ID of the DLT protocol
	 * @param buffer
	 *          buffer containing both state and data in the form
	 * 
	 *          <pre>
	 * +--------------+-------------+
	 * | packet state | packet data |
	 * +--------------+-------------+
	 * </pre>
	 * @throws PeeringException
	 *           the peering exception
	 */
	public JMemoryPacket(int id, ByteBuffer buffer) throws PeeringException {
		this(buffer);

		scan(id);
	}

	/**
	 * Creates a new fully decoded packet from data provides in the buffer. The
	 * buffer contains raw packet data. The packet is peered with the buffer,
	 * allocating new memory if neccessary, and scanned using internal scanner.
	 * 
	 * @param id
	 *          numerical id of first protocol (DLT)
	 * @param buffer
	 *          buffer containing raw packet data
	 */
	public JMemoryPacket(int id, JBuffer buffer) {
		this(buffer);

		scan(id);
	}

	/**
	 * Creates a new fully decoded packet from the hexdump data provided.
	 * 
	 * @param id
	 *          numerical id of first protocol (DLT)
	 * @param hexdump
	 *          hexdump of the packet contents which will loaded into the raw data
	 *          buffer
	 */
	public JMemoryPacket(int id, String hexdump) {
		this(id, FormatUtils.toByteArray(hexdump));
	}

	/**
	 * Initializes the packet's state and data by doing a deep copy of the
	 * contents of the buffer.
	 * 
	 * @param buffer
	 *          buffer containing both state and data in the form
	 * 
	 *          <pre>
	 * +--------------+-------------+
	 * | packet state | packet data |
	 * +--------------+-------------+
	 * </pre>
	 */
	public JMemoryPacket(JBuffer buffer) {
		super(POINTER);

		header.setWirelen(buffer.size());

		final int len = buffer.size();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer); // Make a buffer to buffer copy

		peer(b, 0, len);
		
		header.setWirelen(len);
	}

	/**
	 * Copies both state and data from supplied packet to this packet by
	 * performing a deep copy of the contents of the buffer into packet's internal
	 * memory buffer if that buffer is large enough, otherwise a new buffer is
	 * allocated. Both packet's state and data are then peered with the internal
	 * buffer containing the copy of the supplied buffer
	 * 
	 * @param packet
	 *          source packet
	 */
	public JMemoryPacket(JMemoryPacket packet) {
		super(Type.POINTER);

		transferFrom(packet);
	}

	/**
	 * Copies both state and data from supplied packet to this packet by
	 * performing a deep copy of the contents of the buffer into packet's internal
	 * memory buffer if that buffer is large enough, otherwise a new buffer is
	 * allocated. Both packet's state and data are then peered with the internal
	 * buffer containing the copy of the supplied buffer
	 * 
	 * @param packet
	 *          source packet
	 */
	public JMemoryPacket(JPacket packet) {
		super(Type.POINTER);

		transferFrom(packet);
	}

	/**
	 * Creates a potentially uninitialized packet with the specified memory type.
	 * 
	 * @param type
	 *          type of memory model to use
	 */
	public JMemoryPacket(Type type) {
		super(type);
	}

	/**
	 * Retrieves this packets capture header.
	 * 
	 * @return capture header
	 * @see org.jnetpcap.packet.JPacket#getCaptureHeader()
	 */
	@Override
	public JMemoryHeader getCaptureHeader() {
		return this.header;
	}

	/**
	 * Calculates the total size of this packet which includes the size of the
	 * state structures and packet data.
	 * 
	 * @return total packet length in bytes
	 * @see org.jnetpcap.packet.JPacket#getTotalSize()
	 */
	@Override
	public int getTotalSize() {
		return super.size() + super.state.size();
	}

	/**
	 * Peers the contents of the buffer directly with this packet. No copies are
	 * performed but the packet state and data are expected to be contained within
	 * the buffer with a certain layout as described below:
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +-----+----+
	 * |State|Data|
	 * +-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          Buffer containing packet header, state and data. Position property
	 *          specifies that start within the buffer where to peer the first
	 *          byte.
	 * @return number of bytes peered
	 * @throws PeeringException
	 *           thrown if ByteBuffer is not direct byte buffer type
	 */
	public int peerStateAndData(ByteBuffer buffer) throws PeeringException {
		if (buffer.isDirect() == false) {
			throw new PeeringException("unable to peer a non-direct ByteBuffer");
		}
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * Peers the contents of the buffer directly with this packet. No copies are
	 * performed but the packet state and data are expected to be contained within
	 * the buffer with a certain layout as described below:
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +-----+----+
	 * |State|Data|
	 * +-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing packet header, state and data
	 * @return number of bytes peered
	 */
	public int peerStateAndData(JBuffer buffer) {
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * Peers the contents of the buffer directly with this packet. No copies are
	 * performed but the packet state and data are expected to be contained within
	 * the buffer with a certain layout as described below:
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +-----+----+
	 * |State|Data|
	 * +-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing packet header, state and data
	 * @param offset
	 *          starting offset into the buffer
	 * @return number of bytes peered
	 */
	public int peerStateAndData(JBuffer buffer, int offset) {

		state.peerTo(buffer, offset, State.sizeof(0));
		int o = state.peerTo(buffer, offset, State.sizeof(state.getHeaderCount()));
		o += super.peer(buffer, offset + o, header.caplen());

		return o;
	}

	/**
	 * Changes the wirelen of this packet.
	 * 
	 * @param wirelen
	 *          new wirelen for this packet
	 */
	public void setWirelen(int wirelen) {
		header.setWirelen(wirelen);
	}

	/**
	 * Performs a deep copy of the contents of the buffer into packet's internal
	 * memory buffer if that buffer is large enough, otherwise a new buffer is
	 * allocated. Both packet's state and data are then peered with the internal
	 * buffer containing the copy of the supplied buffer
	 * 
	 * @param buffer
	 *          buffer containing both state and data in the form
	 * 
	 * <pre>
	 *          +--------------+-------------+
	 *          | packet state | packet data |
	 *          +--------------+-------------+
	 * </pre>
	 * 
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(byte[] buffer) {
		JBuffer b = getMemoryBuffer(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * Performs a deep copy of the contents of the buffer into packet's internal
	 * memory buffer if that buffer is large enough, otherwise a new buffer is
	 * allocated. Both packet's state and data are then peered with the internal
	 * buffer containing the copy of the supplied buffer
	 * 
	 * @param buffer
	 *          buffer containing both state and data in the form
	 * 
	 * <pre>
	 *          +--------------+-------------+
	 *          | packet state | packet data |
	 *          +--------------+-------------+
	 * </pre>
	 * 
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(ByteBuffer buffer) {
		final int len = buffer.limit() - buffer.position();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer, 0);

		return peerStateAndData(b, 0);
	}

	/**
	 * Performs a deep copy of the contents of the buffer into packet's internal
	 * memory buffer if that buffer is large enough, otherwise a new buffer is
	 * allocated. Both packet's state and data are then peered with the internal
	 * buffer containing the copy of the supplied buffer
	 * 
	 * @param buffer
	 *          buffer containing both state and data in the form
	 * 
	 * <pre>
	 *          +--------------+-------------+
	 *          | packet state | packet data |
	 *          +--------------+-------------+
	 * </pre>
	 * 
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(JBuffer buffer) {
		final int len = buffer.size();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * Copies both state and data from supplied packet to this packet by
	 * performing a deep copy of the contents of the buffer into packet's internal
	 * memory buffer if that buffer is large enough, otherwise a new buffer is
	 * allocated. Both packet's state and data are then peered with the internal
	 * buffer containing the copy of the supplied buffer
	 * 
	 * @param packet
	 *          source packet
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(JMemoryPacket packet) {
		return packet.transferTo(this);
	}

	/**
	 * Copies both state and data from supplied packet to this packet by
	 * performing a deep copy of the contents of the buffer into packet's internal
	 * memory buffer if that buffer is large enough, otherwise a new buffer is
	 * allocated. Both packet's state and data are then peered with the internal
	 * buffer containing the copy of the supplied buffer
	 * 
	 * @param packet
	 *          source packet
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(JPacket packet) {
		int len = packet.state.size() + packet.size();
		JBuffer mem = getMemoryBuffer(len);

		int o = packet.state.transferTo(mem, 0, packet.state.size(), 0);
		o += packet.transferTo(mem, 0, packet.size(), o);

		return o;
	}

	/**
	 * Copies contents of this packet to buffer. The packets capture state and
	 * packet data are copied to new buffer. After completion of this operation
	 * the complete contents and state of the packet will be transfered to the
	 * buffer. The layout of the buffer data will be as described below. A buffer
	 * with this type of layout is suitable for any transferStateAndData or peer
	 * methods for any buffers that are JMemory based. The buffer has to be large
	 * enough to hold all of the packet content as returned by method
	 * 
	 * @param buffer
	 *          buffer containing both state and data in the form
	 * 
	 *          <pre>
	 * +--------------+-------------+
	 * | packet state | packet data |
	 * +--------------+-------------+
	 * </pre>
	 * @param offset
	 *          the offset
	 * @return number of bytes copied {@link #getTotalSize()}. If the buffer is
	 *         too small and a runtime exception may be thrown.
	 *         <p>
	 *         The buffer layout will look like the following:
	 * 
	 *         <pre>
	 * +-----+----+
	 * |State|Data|
	 * +-----+----+
	 * </pre>
	 * 
	 *         </p>
	 */
	public int transferStateAndDataTo(JBuffer buffer, int offset) {
		int o = state.transferTo(buffer, 0, state.size(), offset);
		o += super.transferTo(buffer, 0, size(), offset + o);

		return o;
	}

	/**
	 * Copies both state and data to the supplied packet from this packet by
	 * performing a deep copy of the contents of the buffer into packet's internal
	 * memory buffer if that buffer is large enough, otherwise a new buffer is
	 * allocated. Both packet's state and data are then peered with the internal
	 * buffer containing the copy of the supplied buffer
	 * 
	 * @param packet
	 *          destination packet
	 * @return number of bytes copied
	 */
	public int transferStateAndDataTo(JMemoryPacket packet) {
		final JBuffer buffer = packet.getMemoryBuffer(this.getTotalSize());

		packet.transferStateAndDataTo(buffer, 0);

		return peerStateAndData(buffer, 0);
	}
}
