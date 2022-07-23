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
package org.jnetpcap.winpcap;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapPktHdr;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.PeeringException;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;

// TODO: Auto-generated Javadoc
/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * Class peered with native <code>pcap_send_queue</code> structure. A queue of
 * raw packets that will be sent to the network with
 * <code>WinPcap.sendqueueTransmit()</code>. The class peers with native C
 * pcap_send_queue structure and allows direct control. The structure can be
 * allocated using WinPcap.sendQueueAlloc method or can be directly instantiated
 * using one o the public constructors.
 * 
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
@Library(jni = Pcap.LIBRARY)
public class WinPcapSendQueue extends JStruct {

	static {
		JNILibrary.register(WinPcapSendQueue.class);
	}

	/**
	 * Constant used to determine the default queue size which is 64Kb (1024 *
	 * 64).
	 */
	public final static int DEFAULT_QUEUE_SIZE = 64 * 1024;

	/** The Constant STRUCT_NAME. */
	public final static String STRUCT_NAME = "pcap_send_queue";

	/**
	 * Returns sizeof struct pcap_send_queue.
	 * 
	 * @return size of structure
	 */
	public native static int sizeof();

	/** The buffer. */
	private final JBuffer buffer;

	/**
	 * Allocates default size buffer for use as a send queue.
	 */
	public WinPcapSendQueue() {
		this(DEFAULT_QUEUE_SIZE);
	}

	/**
	 * Creates a sendqueue by allocating a buffer to hold the supplied data. The
	 * data array is copied into the buffer.
	 * 
	 * @param data
	 *          data to be copied into the queue
	 */
	public WinPcapSendQueue(byte[] data) {
		super(STRUCT_NAME, sizeof());

		this.buffer = new JBuffer(data.length);
		this.buffer.order(ByteOrder.nativeOrder()); // Force byte ordering

		this.buffer.setByteArray(0, data);
		setMaxLen(data.length);
	}

	/**
	 * <p>
	 * The queue uses the supplied byte buffer which holds the buffers contents.
	 * The buffer must a direct buffer, array based buffers will be rejected and
	 * an exception thrown. The properties of the buffer are used as follows. The
	 * start of the buffer is always with index 0, and end of queue content at
	 * current buffer's limit property (comparible to pcap_send_queue.len). The
	 * capacity property (comparible to pcap_send_queue.maxlen) determines maximum
	 * amount of data that can be further stored in the buffer.
	 * </p>
	 * <p>
	 * Note that changing properties of the buffer after creating this queue
	 * object, will have immediate effect up on the queue. You do not have to use
	 * the queue's provided methods to change the limit property. This should
	 * allow of external addition of the
	 * </p>
	 * 
	 * @param buffer
	 *          a direct buffer containing the data to be send
	 * @throws PeeringException
	 *           the peering exception
	 */
	public WinPcapSendQueue(ByteBuffer buffer) throws PeeringException {
		super(STRUCT_NAME, sizeof());
		this.buffer = new JBuffer(Type.POINTER);
		this.buffer.order(ByteOrder.nativeOrder()); // Force byte ordering

		if (buffer.isDirect() == false) {
			throw new IllegalArgumentException("Only direct buffers are accepted. "
					+ "See ByteBuffer.allocateDirect method.");
		}
		this.buffer.peer(buffer);
		setMaxLen(this.buffer.size());
	}

	/**
	 * Allocates specific queue <code>size</code>.
	 * 
	 * @param size
	 *          size of the queue in bytes
	 */
	public WinPcapSendQueue(int size) {
		super(STRUCT_NAME, sizeof());
		this.buffer = new JBuffer(size);
		this.buffer.order(ByteOrder.nativeOrder()); // Force byte ordering

		setMaxLen(size);
		setBuffer(buffer);
	}

	/**
	 * Gets the buffer containing the packets to be sent.
	 * 
	 * @return buffer containing the packets to be sent
	 */
	public JBuffer getBuffer() {
		return buffer;
	}

	/**
	 * Gets the current size of the queue, in bytes.
	 * 
	 * @return current size of the queue, in bytes
	 */
	public native int getLen();

	/**
	 * Gets the maximum size of the the queue, in bytes. This variable contains
	 * the size of the buffer field.
	 * 
	 * @return maximum size of the the queue, in bytes
	 */
	public native int getMaxLen();

	/**
	 * Inc len.
	 * 
	 * @param delta
	 *          the delta
	 * @return the int
	 */
	public native int incLen(int delta);

	/**
	 * Add a packet to a send queue. This method adds a packet at the end of the
	 * send queue pointed by the queue parameter. <code>hdr</code> points to a
	 * PcapPktHdr structure with the timestamp and the length of the packet, data
	 * points to a buffer with the data of the packet. The PcapPktHdr structure is
	 * the same used by WinPcap and libpcap to store the packets in a file,
	 * therefore sending a capture file is straightforward. 'Raw packet' means
	 * that the sending application will have to include the protocol headers,
	 * since every packet is sent to the network 'as is'. The CRC of the packets
	 * needs not to be calculated, because it will be transparently added by the
	 * network interface.
	 * 
	 * @param header
	 *          all fields need to be initialized as they are all used
	 * @param data
	 *          Buffer containing packet data. The buffer's position and limit
	 *          properties determine the area of the buffer to be copied into the
	 *          queue. The length of the data must much what is in the header.
	 *          Also the queue has to be large enough to hold all of the data, or
	 *          an exception will be thrown.
	 * @return 0 (Pcap.OK) on success; exception thrown on failure
	 */
	public int queue(PcapHeader header, byte[] data) {
		return queue(header, new JBuffer(data));
	}

	/**
	 * Add a packet to a send queue. This method adds a packet at the end of the
	 * send queue pointed by the queue parameter. <code>hdr</code> points to a
	 * PcapPktHdr structure with the timestamp and the length of the packet, data
	 * points to a buffer with the data of the packet. The PcapPktHdr structure is
	 * the same used by WinPcap and libpcap to store the packets in a file,
	 * therefore sending a capture file is straightforward. 'Raw packet' means
	 * that the sending application will have to include the protocol headers,
	 * since every packet is sent to the network 'as is'. The CRC of the packets
	 * needs not to be calculated, because it will be transparently added by the
	 * network interface.
	 * 
	 * @param header
	 *          all fields need to be initialized as they are all used
	 * @param data
	 *          Buffer containing packet data. The buffer's position and limit
	 *          properties determine the area of the buffer to be copied into the
	 *          queue. The length of the data must much what is in the header.
	 *          Also the queue has to be large enough to hold all of the data, or
	 *          an exception will be thrown.
	 * @return 0 (Pcap.OK) on success; exception thrown on failure
	 */
	public int queue(PcapHeader header, ByteBuffer data) {
		return queue(header, new JBuffer(data));
	}

	/**
	 * Add a packet to a send queue. This method adds a packet at the end of the
	 * send queue pointed by the queue parameter. <code>hdr</code> points to a
	 * PcapPktHdr structure with the timestamp and the length of the packet, data
	 * points to a buffer with the data of the packet. The PcapPktHdr structure is
	 * the same used by WinPcap and libpcap to store the packets in a file,
	 * therefore sending a capture file is straightforward. 'Raw packet' means
	 * that the sending application will have to include the protocol headers,
	 * since every packet is sent to the network 'as is'. The CRC of the packets
	 * needs not to be calculated, because it will be transparently added by the
	 * network interface.
	 * 
	 * @param header
	 *          all fields need to be initialized as they are all used
	 * @param data
	 *          Buffer containing packet data. The buffer's position and limit
	 *          properties determine the area of the buffer to be copied into the
	 *          queue. The length of the data must much what is in the header.
	 *          Also the queue has to be large enough to hold all of the data, or
	 *          an exception will be thrown.
	 * @return 0 (Pcap.OK) on success; exception thrown on failure
	 */
	public int queue(PcapHeader header, JBuffer data) {

		header.transferTo(buffer, 0, header.size(), getLen());
		setLen(getLen() + header.size());

		data.transferTo(buffer, 0, data.size(), getLen());
		setLen(getLen() + data.size());

		return Pcap.OK;
	}

	/**
	 * Add a packet to a send queue. This method adds a packet at the end of the
	 * send queue pointed by the queue parameter. <code>hdr</code> points to a
	 * PcapPktHdr structure with the timestamp and the length of the packet, data
	 * points to a buffer with the data of the packet. The PcapPktHdr structure is
	 * the same used by WinPcap and libpcap to store the packets in a file,
	 * therefore sending a capture file is straightforward. 'Raw packet' means
	 * that the sending application will have to include the protocol headers,
	 * since every packet is sent to the network 'as is'. The CRC of the packets
	 * needs not to be calculated, because it will be transparently added by the
	 * network interface.
	 * 
	 * @param hdr
	 *          all fields need to be initialized as they are all used
	 * @param data
	 *          Buffer containing packet data. The length of the data must much
	 *          what is in the header. Also the queue has to be large enough to
	 *          hold all of the data, or an exception will be thrown.
	 * @return 0 on success; exception thrown on failure
	 * @deprecated replaced with new versions of the same method
	 */
	@Deprecated
	public int queue(PcapPktHdr hdr, byte[] data) {

		if (data.length != hdr.getCaplen()) {
			throw new IllegalArgumentException("Buffer length "
					+ "does not equal length in packet header");
		}

		int p = getLen();

		/*
		 * Write the packet header first
		 */
		buffer.setInt(p, (int) hdr.getSeconds());
		buffer.setInt(p + 4, hdr.getUseconds());
		buffer.setInt(p + 8, hdr.getCaplen());
		buffer.setInt(p + 12, hdr.getLen());

		buffer.setByteArray(p + 16, data);
		incLen(16 + data.length);

		return 0;
	}

	/**
	 * Add a packet to a send queue. This method adds a packet at the end of the
	 * send queue pointed by the queue parameter. <code>hdr</code> points to a
	 * PcapPktHdr structure with the timestamp and the length of the packet, data
	 * points to a buffer with the data of the packet. The PcapPktHdr structure is
	 * the same used by WinPcap and libpcap to store the packets in a file,
	 * therefore sending a capture file is straightforward. 'Raw packet' means
	 * that the sending application will have to include the protocol headers,
	 * since every packet is sent to the network 'as is'. The CRC of the packets
	 * needs not to be calculated, because it will be transparently added by the
	 * network interface.
	 * 
	 * @param hdr
	 *          all fields need to be initialized as they are all used
	 * @param data
	 *          Buffer containing packet data. The buffer's position and limit
	 *          properties determine the area of the buffer to be copied into the
	 *          queue. The length of the data must much what is in the header.
	 *          Also the queue has to be large enough to hold all of the data, or
	 *          an exception will be thrown.
	 * @return 0 on success; exception thrown on failure
	 * @deprecated replaced with new versions of the same method
	 */
	@Deprecated
	public int queue(PcapPktHdr hdr, ByteBuffer data) {

		int length = data.limit() - data.position();
		if (length != hdr.getCaplen()) {
			throw new IllegalArgumentException("Buffer length (limit - position) "
					+ "does not equal length in packet header");
		}

		int p = getLen();

		/*
		 * Write the packet header first
		 */
		buffer.setInt(p, (int) hdr.getSeconds());
		buffer.setInt(p + 4, hdr.getUseconds());
		buffer.setInt(p + 8, hdr.getCaplen());
		buffer.setInt(p + 12, hdr.getLen());

		buffer.setByteBuffer(p + 16, data);
		incLen(16 + length);

		return 0;
	}

	/**
	 * Sets the buffer.
	 * 
	 * @param buffer
	 *          the new buffer
	 */
	private native void setBuffer(JBuffer buffer);

	/**
	 * Sets the peered <code>pcap_send_queue.len</code> field which specifies the
	 * urrent size of the queue, in bytes.
	 * 
	 * @param len
	 *          current size of the queue, in bytes
	 */
	public native void setLen(int len);

	/**
	 * Sets the max len.
	 * 
	 * @param len
	 *          the new max len
	 */
	public native void setMaxLen(int len);
}
