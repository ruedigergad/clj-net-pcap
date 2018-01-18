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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.nio.JNumber;
import org.jnetpcap.packet.PeeringException;

// TODO: Auto-generated Javadoc
/**
 * The Class SlidingBuffer.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class SlidingBuffer {

	/** The left sequence. */
	private long leftSequence = 0L;

	/** The right sequence. */
	private long rightSequence = 0L;

	/** The storage. */
	private final JBuffer storage;

	/** The size. */
	private final int size;

	/**
	 * Instantiates a new sliding buffer.
	 * 
	 * @param size
	 *          the size
	 */
	public SlidingBuffer(int size) {
		this.size = size;

		/*
		 * Allocate round robin buffer with padding so that we can duplicate a few
		 * bytes at the right edge of the real offset. This way if we're asked to
		 * read a value that is wrapped around mid way at the end of the buffer, we
		 * can just safely read it since those bytes have been duplicated.
		 */
		this.storage = JMemoryPool.buffer(size + JNumber.Type.getBiggestSize());
	}

	/**
	 * Find ut f8 string.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param delimeter
	 *          the delimeter
	 * @return the int
	 */
	public int findUTF8String(long sequence, char... delimeter) {
		return this.storage.findUTF8String(map(sequence), delimeter);
	}

	/**
	 * Gets the byte.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the byte
	 */
	public byte getByte(long sequence) {
		return this.storage.getByte(map(sequence));
	}

	/**
	 * Gets the byte array.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param array
	 *          the array
	 * @return the byte array
	 */
	public byte[] getByteArray(long sequence, byte[] array) {
		return this.storage.getByteArray(map(sequence), array);
	}

	/**
	 * Gets the byte array.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param size
	 *          the size
	 * @return the byte array
	 */
	public byte[] getByteArray(long sequence, int size) {
		return this.storage.getByteArray(map(sequence), size);
	}

	/**
	 * Gets the double.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the double
	 */
	public double getDouble(long sequence) {
		return this.storage.getDouble(map(sequence));
	}

	/**
	 * Gets the float.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the float
	 */
	public float getFloat(long sequence) {
		return this.storage.getFloat(map(sequence));
	}

	/**
	 * Gets the int.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the int
	 */
	public int getInt(long sequence) {
		return this.storage.getInt(map(sequence));
	}

	/**
	 * Gets the long.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the long
	 */
	public long getLong(long sequence) {
		return this.storage.getLong(map(sequence));
	}

	/**
	 * Gets the short.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the short
	 */
	public short getShort(long sequence) {
		return this.storage.getShort(map(sequence));
	}

	/**
	 * Gets the u byte.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the u byte
	 */
	public int getUByte(long sequence) {
		return this.storage.getUByte(map(sequence));
	}

	/**
	 * Gets the u int.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the u int
	 */
	public long getUInt(long sequence) {
		return this.storage.getUInt(map(sequence));
	}

	/**
	 * Gets the u short.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the u short
	 */
	public int getUShort(long sequence) {
		return this.storage.getUShort(map(sequence));
	}

	/**
	 * Gets the uT f8 char.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the uT f8 char
	 */
	public char getUTF8Char(long sequence) {
		return this.storage.getUTF8Char(map(sequence));
	}

	/**
	 * Gets the uT f8 string.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param delimeter
	 *          the delimeter
	 * @return the uT f8 string
	 */
	public String getUTF8String(long sequence, char... delimeter) {
		return this.storage.getUTF8String(map(sequence), delimeter);
	}

	/**
	 * Gets the uT f8 string.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param length
	 *          the length
	 * @return the uT f8 string
	 */
	public String getUTF8String(long sequence, int length) {
		return this.storage.getUTF8String(map(sequence), length);
	}

	/**
	 * Gets the uT f8 string.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param buf
	 *          the buf
	 * @param delimeter
	 *          the delimeter
	 * @return the uT f8 string
	 */
	public StringBuilder getUTF8String(
	    int sequence,
	    StringBuilder buf,
	    char... delimeter) {
		return this.storage.getUTF8String(map(sequence), buf, delimeter);
	}

	/**
	 * Gets the uT f8 string.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param buf
	 *          the buf
	 * @param length
	 *          the length
	 * @return the uT f8 string
	 */
	public StringBuilder getUTF8String(
	    long sequence,
	    StringBuilder buf,
	    int length) {
		return this.storage.getUTF8String(map(sequence), buf, length);
	}

	/**
	 * Hash code.
	 * 
	 * @return the int
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return this.storage.hashCode();
	}

	/**
	 * Checks if is initialized.
	 * 
	 * @return true, if is initialized
	 */
	public boolean isInitialized() {
		return this.storage.isInitialized();
	}

	/**
	 * Checks if is j memory based owner.
	 * 
	 * @return true, if is j memory based owner
	 */
	public boolean isJMemoryBasedOwner() {
		return this.storage.isJMemoryBasedOwner();
	}

	/**
	 * Checks if is owner.
	 * 
	 * @return true, if is owner
	 */
	public final boolean isOwner() {
		return this.storage.isOwner();
	}

	/**
	 * Checks if is readonly.
	 * 
	 * @return true, if is readonly
	 */
	public boolean isReadonly() {
		return this.storage.isReadonly();
	}

	/**
	 * Order.
	 * 
	 * @return the byte order
	 */
	public ByteOrder order() {
		return this.storage.order();
	}

	/**
	 * Order.
	 * 
	 * @param order
	 *          the order
	 */
	public void order(ByteOrder order) {
		this.storage.order(order);
	}

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @return the int
	 * @throws PeeringException
	 *           the peering exception
	 */
	public int peer(ByteBuffer peer) throws PeeringException {
		return this.storage.peer(peer);
	}

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 * @throws IndexOutOfBoundsException
	 *           the index out of bounds exception
	 */
	public int peer(JBuffer peer, int offset, int length)
	    throws IndexOutOfBoundsException {
		return this.storage.peer(peer, offset, length);
	}

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @return the int
	 */
	public int peer(JBuffer peer) {
		return this.storage.peer(peer);
	}

	/**
	 * Peer.
	 * 
	 * @param src
	 *          the src
	 * @return the int
	 */
	public int peer(JMemory src) {
		return this.storage.peer(src);
	}

	/**
	 * Sets the byte.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setByte(long sequence, byte value) {
		this.storage.setByte(map(sequence), value);
	}

	/**
	 * Sets the byte array.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param array
	 *          the array
	 */
	public void setByteArray(long sequence, byte[] array) {
		this.storage.setByteArray(map(sequence), array);
	}

	/**
	 * Sets the byte buffer.
	 * 
	 * @param i
	 *          the i
	 * @param data
	 *          the data
	 */
	public void setByteBuffer(int i, ByteBuffer data) {
		this.storage.setByteBuffer(i, data);
	}

	/**
	 * Sets the double.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setDouble(long sequence, double value) {
		this.storage.setDouble(map(sequence), value);
	}

	/**
	 * Sets the float.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setFloat(long sequence, float value) {
		this.storage.setFloat(map(sequence), value);
	}

	/**
	 * Sets the int.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setInt(long sequence, int value) {
		this.storage.setInt(map(sequence), value);
	}

	/**
	 * Sets the long.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setLong(long sequence, long value) {
		this.storage.setLong(map(sequence), value);
	}

	/**
	 * Sets the short.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setShort(long sequence, short value) {
		this.storage.setShort(map(sequence), value);
	}

	/**
	 * Sets the u byte.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setUByte(long sequence, int value) {
		this.storage.setUByte(map(sequence), value);
	}

	/**
	 * Sets the u int.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setUInt(long sequence, long value) {
		this.storage.setUInt(map(sequence), value);
	}

	/**
	 * Map.
	 * 
	 * @param sequence
	 *          the sequence
	 * @return the int
	 */
	private int map(long sequence) {

		return (int) (sequence - leftSequence);
	}

	/**
	 * Sets the u short.
	 * 
	 * @param sequence
	 *          the sequence
	 * @param value
	 *          the value
	 */
	public void setUShort(long sequence, int value) {
		this.storage.setUShort(map(sequence), value);
	}

	/**
	 * Length.
	 * 
	 * @return the int
	 */
	public int length() {
		return (int) (rightSequence - leftSequence);
	}

	/**
	 * To debug string.
	 * 
	 * @return the string
	 */
	public String toDebugString() {
		return this.storage.toDebugString();
	}

	/**
	 * To hexdump.
	 * 
	 * @return the string
	 */
	public String toHexdump() {
		return this.storage.toHexdump();
	}

	/**
	 * To hexdump.
	 * 
	 * @param length
	 *          the length
	 * @param address
	 *          the address
	 * @param text
	 *          the text
	 * @param data
	 *          the data
	 * @return the string
	 */
	public String toHexdump(
	    int length,
	    boolean address,
	    boolean text,
	    boolean data) {
		return this.storage.toHexdump(length, address, text, data);
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return this.storage.toString();
	}

	/**
	 * Transfer from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferFrom(byte[] buffer) {
		return this.storage.transferFrom(buffer);
	}

	/**
	 * Transfer from.
	 * 
	 * @param src
	 *          the src
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	public int transferFrom(ByteBuffer src, int dstOffset) {
		return this.storage.transferFrom(src, (int) (dstOffset - leftSequence));
	}

	/**
	 * Transfer from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferFrom(JBuffer buffer) {
		advance(buffer.size());
		return this.storage.transferFrom(buffer);
	}

	/**
	 * Advance.
	 * 
	 * @param size
	 *          the size
	 */
	private void advance(int size) {
		if (rightSequence + size > this.size) {
		}
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	public int transferTo(ByteBuffer dst, int srcOffset, int length) {
		return this.storage.transferTo(dst, (int) (srcOffset - leftSequence),
		    length);
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @return the int
	 */
	public int transferTo(ByteBuffer dst) {
		return this.storage.transferTo(dst);
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	public int transferTo(JBuffer dst, int srcOffset, int length, int dstOffset) {
		return this.storage.transferTo(dst, (int) (srcOffset - leftSequence),
		    length, dstOffset);
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @return the int
	 */
	public int transferTo(JBuffer dst) {
		return this.storage.transferTo(dst);
	}

}
