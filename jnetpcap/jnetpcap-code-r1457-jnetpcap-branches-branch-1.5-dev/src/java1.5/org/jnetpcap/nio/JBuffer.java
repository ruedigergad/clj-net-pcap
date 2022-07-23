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
package org.jnetpcap.nio;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PeeringException;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;

/**
 * A direct buffer stored in native memory.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Library(jni = Pcap.LIBRARY, preload = JMemory.class)
public class JBuffer extends JMemory {

	/**
	 * 
	 */
	static {
		JNILibrary.register(JBuffer.class);
	}

	/**
	 * JNI Ids.
	 */
	@LibraryInitializer
	private native static void initIds();

	/** True means BIG endian, false means LITTLE endian byte order. */
	private volatile boolean order =
			(ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN);

	/** True means buffer is readonly, false means read/write buffer type. */
	private boolean readonly = false;

	/**
	 * Creates a.
	 * 
	 * @param type
	 *          memory model
	 */
	public JBuffer(Type type) {
		super(type);
	}

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param peer
	 *          the peer
	 */
	public JBuffer(final ByteBuffer peer) {
		super(peer);
	}

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param size
	 *          the size
	 */
	public JBuffer(final int size) {
		super(size);
	}

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param peer
	 *          the peer
	 */
	public JBuffer(final JMemory peer) {
		super(peer);
	}

	/**
	 * Check.
	 * 
	 * @param index
	 *          the index
	 * @param len
	 *          the len
	 * @param address
	 *          the address
	 * @return the int
	 */
	private final int check(int index, int len, long address) {
		if (address == 0L) {
			throw new NullPointerException();
		}

		if (index < 0 || index + len > size) {
			throw new BufferUnderflowException();
		}

		return index;
	}

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param data
	 *          the data
	 */
	public JBuffer(byte[] data) {
		super(data.length);
		setByteArray(0, data);
	}

	/**
	 * Gets a signed 8-bit value.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value from the buffer
	 */
	public byte getByte(int index) {
		return getByte0(physical, check(index, 1, physical));
	}

	/**
	 * Gets the byte0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @return the byte0
	 */
	private native static byte getByte0(long address, int index);

	/**
	 * Gets byte data from buffer and stores it in supplied array buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param array
	 *          byte array used to store the result where the length of the byte
	 *          array determines the number of bytes to be copied from the buffer
	 * @return same array object passed in
	 */
	public byte[] getByteArray(int index, byte[] array) {
		return getByteArray(index, array, 0, array.length);
	}

	/**
	 * Gets the byte data from buffer and stores into newly allocated byte array.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param size
	 *          number of bytes to copy and the size of the newly allocated byte
	 *          array
	 * @return reference to new byte array containing the copied data
	 */
	public byte[] getByteArray(int index, int size) {
		return getByteArray(index, new byte[size], 0, size);
	}

	/**
	 * Reads data from JBuffer into user supplied array.
	 * 
	 * @param index
	 *          starting position in the JBuffer
	 * @param array
	 *          destination array
	 * @param offset
	 *          starting position in the destination array
	 * @param length
	 *          maximum number of bytes to copy
	 * @return the actual number of bytes copied which could be less then
	 *         requested due to size of the JBuffer
	 */
	public byte[] getByteArray(int index, byte[] array, int offset, int length) {

		if (array == null) {
			throw new NullPointerException();
		}

		if (offset < 0 || offset + length > array.length) {
			throw new ArrayIndexOutOfBoundsException();
		}

		return getByteArray0(physical,
				check(index, length, physical),
				array,
				array.length,
				offset,
				length);
	}

	/**
	 * Gets the byte array0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @param array
	 *          the array
	 * @param arrayLength
	 *          the array length
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the byte array0
	 */
	private static native byte[] getByteArray0(long address,
			int index,
			byte[] array,
			int arrayLength,
			int offset,
			int length);

	/**
	 * Gets the java double value out of the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public double getDouble(int index) {
		return Double.longBitsToDouble(getLong0(physical, order, check(index, 8, physical)));
	}

	/**
	 * Gets the double0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the double0
	 */
	private static native double getDouble0(long address, boolean order, int index);

	/**
	 * Gets the java float value out of the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public float getFloat(int index) {
		return Float.intBitsToFloat(getInt0(physical, order, check(index, 4, physical)));
	}

	/**
	 * Gets the float0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the float0
	 * @deprecated use {@link Float#intBitsToFloat(int)} and {@link #getInt0(long, boolean, int)}
	 */
	private static native float getFloat0(long address, boolean order, int index);

	/**
	 * Gets the java signed integer value from the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public int getInt(int index) {
		return getInt0(physical, order, check(index, 4, physical));
	}

	/**
	 * Gets the int0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the int0
	 */
	private static native int getInt0(long address, boolean order, int index);

	/**
	 * Gets the java signed long value from the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public long getLong(int index) {
		return getLong0(physical, order, check(index, 8, physical));
	}

	/**
	 * Gets the long0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the long0
	 */
	private static native long getLong0(long address, boolean order, int index);

	/**
	 * Gets the java signed short value from the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public short getShort(int index) {
		return getShort0(physical, order, check(index, 2, physical));
	}

	/**
	 * Gets the short0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the short0
	 */
	private static native short getShort0(long address, boolean order, int index);

	/**
	 * Gets the java usigned byte value.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer as next bigger java primitive type so
	 *         that the sign of the value can be preserved since java does not
	 *         allow unsigned primitives
	 */
	public int getUByte(int index) {
		return getUByte0(physical, check(index, 1, physical));
	}

	/**
	 * Gets the u byte0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @return the u byte0
	 */
	private static native int getUByte0(long address, int index);

	/**
	 * Gets the java usigned int value.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer as next bigger java primitive type so
	 *         that the sign of the value can be preserved since java does not
	 *         allow unsigned primitives
	 */
	public long getUInt(int index) {
		return getUInt0(physical, order, check(index, 4, physical));
	}

	/**
	 * Gets the u int0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the u int0
	 */
	private static native long getUInt0(long address, boolean order, int index);

	/**
	 * Gets the java usigned short value.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer as next bigger java primitive type so
	 *         that the sign of the value can be preserved since java does not
	 *         allow unsigned primitives
	 */
	public int getUShort(int index) {
		return getUShort0(physical, order, check(index, 2, physical));
	}

	/**
	 * Gets the u short0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the u short0
	 */
	private static native int getUShort0(long address, boolean order, int index);

	/**
	 * Find the delimiter array of chars within the buffer.
	 * 
	 * @param index
	 *          starting offset into the buffer
	 * @param delimeter
	 *          array of chars to search for
	 * @return number of delimeter chars matched
	 */
	public int findUTF8String(int index, char... delimeter) {

		final int size = size();

		int searchedLength = 0;
		int match = 0;
		for (int i = index; i < size; i++) {

			char c = getUTF8Char(i);
			char d = delimeter[match];

			if (Character.isDefined(c) == false) {
				break;
			}

			if (d == c) {
				match++;

				if (match == delimeter.length) {
					searchedLength = i - index + 1;
					break;
				}
			} else {
				match = 0;
			}
		}

		return searchedLength;
	}

	/**
	 * Retrieves all the characters from the buffer upto the delimiter char
	 * sequence.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param buf
	 *          string buffer where to store the string retrieved from the buffer
	 * @param delimeter
	 *          array of chars which will mark the end of the string
	 * @return the string buffer containing the retrieved string
	 */
	public StringBuilder getUTF8String(int index,
			StringBuilder buf,
			char... delimeter) {

		final int size = size();
		final int len = index + size;

		int match = 0;
		for (int i = index; i < len; i++) {
			if (i >= size) {
				return buf;
			}

			if (match == delimeter.length) {
				break;
			}

			char c = getUTF8Char(i);
			buf.append(c);

			if (delimeter[match] == c) {
				match++;
			} else {
				match = 0;
			}
		}

		return buf;
	}

	/**
	 * Retrieves all the characters from the buffer upto the delimiter char
	 * sequence.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param delimeter
	 *          array of chars which will mark the end of the string
	 * @return the string retrieved from the buffer
	 */
	public String getUTF8String(int index, char... delimeter) {
		final StringBuilder buf =
				getUTF8String(index, new StringBuilder(), delimeter);

		return buf.toString();
	}

	/**
	 * Converts raw bytes to a java string. The length is the maximum length of
	 * the string to return.
	 * 
	 * @param index
	 *          byte index into the buffer to start
	 * @param buf
	 *          string buffer where the retrieved string is stored
	 * @param length
	 *          number of bytes to convert
	 * @return buffer containing the retrieved string
	 */
	public StringBuilder getUTF8String(int index, StringBuilder buf, int length) {
		final int len = index + ((size() < length) ? size() : length);

		for (int i = index; i < len; i++) {
			char c = getUTF8Char(i);
			buf.append(c);
		}

		return buf;
	}

	/**
	 * Gets the specified number of characters as a string.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param length
	 *          number of UTF8 characters to retrieve
	 * @return retrived string
	 */
	public String getUTF8String(int index, int length) {
		return getUTF8String(index, new StringBuilder(), length).toString();
	}

	/**
	 * Converts a single byte to a java char.
	 * 
	 * @param index
	 *          index into the buffer
	 * @return converted UTF8 char
	 */
	public char getUTF8Char(int index) {
		return (char) getUByte(index);
	}

	/**
	 * Checks if this buffer is readonly. Read only buffers do not allow any
	 * mutable operations to be performed on the buffer.
	 * 
	 * @return true if this buffer is read-only, otherwise false
	 */
	public boolean isReadonly() {
		return readonly;
	}

	/**
	 * Gets the byte-order of this buffer. The buffer allows big and little endian
	 * byte ordering of the integer values accessed by this buffer.
	 * 
	 * @return byte order of this buffer
	 */
	public ByteOrder order() {
		return (order) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
	}

	/**
	 * Sets the byte ordering of integers for this buffer.
	 * 
	 * @param order
	 *          the new byte order for this integer
	 */
	public void order(final ByteOrder order) {
		this.order = (order == ByteOrder.BIG_ENDIAN);
	}

	/**
	 * Peers this buffer with a new buffer. The peer buffer's properties position
	 * and limit are used as starting and ending offsets for the peer operation.
	 * 
	 * @param peer
	 *          the buffer to peer with
	 * @return number of byte peered
	 * @throws PeeringException
	 *           the peering exception
	 */
	@Override
	public int peer(final ByteBuffer peer) throws PeeringException {
		setReadonly(peer.isReadOnly());
		return super.peer(peer);
	}

	/**
	 * Peers this buffer with the new buffer. The entire range of the buffer are
	 * peered.
	 * 
	 * @param peer
	 *          the buffer to peer with
	 * @return number of bytes peered
	 */
	public int peer(final JBuffer peer) {
		setReadonly(peer.isReadonly());
		return super.peer(peer);
	}

	/**
	 * Peers this buffer with a new buffer.
	 * 
	 * @param peer
	 *          buffer to peer with
	 * @param offset
	 *          offset into the new peer buffer
	 * @param length
	 *          number of bytes to peer
	 * @return number of bytes peered
	 * @throws IndexOutOfBoundsException
	 *           if offset and/or length are out of bounds
	 */
	public int peer(final JBuffer peer, final int offset, final int length)
			throws IndexOutOfBoundsException {
		setReadonly(peer.isReadonly());
		return super.peer(peer, offset, length);
	}

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new value to be stored in the buffer
	 */
	public void setByte(int index, byte value) {
		setByte0(physical, check(index, 1, physical), value);
	}

	/**
	 * Sets the byte0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setByte0(long address, int index, byte value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param array
	 *          Array containing data to be set within the buffer. The length of
	 *          the buffer determines the number of bytes to be copied into the
	 *          buffer.
	 */
	public void setByteArray(int index, byte[] array) {
		setByteArray0(physical,
				check(index, array.length, physical),
				array,
				array.length);
	}

	/**
	 * Sets the byte array0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @param array
	 *          the array
	 * @param arrayLength
	 *          the array length
	 */
	private static native void setByteArray0(long address,
			int index,
			byte[] array,
			int arrayLength);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new double value to be stored within the buffer
	 */
	public void setDouble(int index, double value) {
		setDouble0(physical, order, check(index, 8, physical), value);
	}

	/**
	 * Sets the double0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setDouble0(long address,
			boolean order,
			int index,
			double value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new float value to be stored within the buffer
	 */
	public void setFloat(int index, float value) {
		setFloat0(physical, order, check(index, 4, physical), value);
	}

	/**
	 * Sets the float0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setFloat0(long address,
			boolean order,
			int index,
			float value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new int value to be stored within the buffer
	 */
	public void setInt(int index, int value) {
		setInt0(physical, order, check(index, 4, physical), value);
	}

	/**
	 * Sets the int0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setInt0(long address,
			boolean order,
			int index,
			int value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new long value to be stored within the buffer
	 */
	public void setLong(int index, long value) {
		setLong0(physical, order, check(index, 8, physical), value);
	}

	/**
	 * Sets the long0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setLong0(long address,
			boolean order,
			int index,
			long value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new short value to be stored within the buffer
	 */
	public void setShort(int index, short value) {
		setShort0(physical, order, check(index, 2, physical), value);
	}

	/**
	 * Sets the short0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public static native void setShort0(long address,
			boolean order,
			int index,
			short value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new usigned byte value to be stored within the buffer
	 */
	public void setUByte(int index, int value) {
		setUByte0(physical, check(index, 1, physical), value);
	}

	/**
	 * Sets the u byte0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setUByte0(long address, int index, int value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new usigned int value to be stored within the buffer
	 */
	public void setUInt(int index, long value) {
		setUInt0(physical, order, check(index, 4, physical), value);
	}

	/**
	 * Sets the u int0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setUInt0(long address,
			boolean order,
			int index,
			long value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new unsigned short value to be stored within the buffer
	 */
	public void setUShort(int index, int value) {
		setUShort0(physical, order, check(index, 2, physical), value);
	}

	/**
	 * Sets the u short0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setUShort0(long address,
			boolean order,
			int index,
			int value);

	/**
	 * Copies contents of the supplied buffer into this buffer.
	 * 
	 * @param buffer
	 *          Source buffer to copy from. The array length determines the number
	 *          of bytes to copy.
	 * @return number of bytes copied
	 */
	@Override
	public int transferFrom(byte[] buffer) {
		return super.transferFrom(buffer);
	}

	/**
	 * Copies contents of the supplied buffer into this buffer.
	 * 
	 * @param src
	 *          Source buffer to copy from. The position and limit properties of
	 *          the buffer determine the bounds of the copy.
	 * @param dstOffset
	 *          offset into this buffer where to start the copy
	 * @return number of bytes copied
	 */
	@Override
	public int transferFrom(final ByteBuffer src, final int dstOffset) {
		return super.transferFrom(src, dstOffset);
	}

	/**
	 * Copies contents of the supplied buffer into this buffer.
	 * 
	 * @param buffer
	 *          Source buffer. The length of the source buffer determines the
	 *          number of bytes to be copied.
	 * @return number of bytes copied
	 */
	public int transferFrom(JBuffer buffer) {
		return buffer.transferTo(this);
	}

	/**
	 * Copies contents of this buffer into supplied buffer.
	 * 
	 * @param dst
	 *          destination buffer where to copy data to
	 * @param srcOffset
	 *          offset into this buffer where to start the copy
	 * @param length
	 *          number of bytes to copy
	 * @return number of bytes copied
	 */
	@Override
	public int transferTo(final ByteBuffer dst,
			final int srcOffset,
			final int length) {
		return super.transferTo(dst, srcOffset, length);
	}

	/**
	 * Copies the contents of this buffer into the supplied buffer.
	 * 
	 * @param dst
	 *          Destination buffer where to copy to. The number of bytes copied is
	 *          determined by the size of source buffer.
	 * @return number of bytes copied
	 */
	public int transferTo(final JBuffer dst) {
		return super.transferTo(dst);
	}

	/**
	 * Copies the contents of thsi buffer into the supplied buffer.
	 * 
	 * @param dst
	 *          destination buffer where to copy to
	 * @param srcOffset
	 *          offset into the source buffer where to start copy from
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          offset into the destination buffer where to start copy to
	 * @return number of bytes copied
	 */
	@Override
	public int transferTo(final JBuffer dst,
			final int srcOffset,
			final int length,
			final int dstOffset) {
		return super.transferTo(dst, srcOffset, length, dstOffset);
	}

	/**
	 * Sets this buffer as either read-only or read-write. Read-only mode disables
	 * all mutable operations on this buffer.
	 * 
	 * @param readonly
	 *          buffer accessor mode
	 */
	private final void setReadonly(boolean readonly) {
		this.readonly = readonly;
	}

	/**
	 * Sets data within this buffer.
	 * 
	 * @param index
	 *          offset into this buffer
	 * @param data
	 *          data to copy into this buffer. The position and limit of the data
	 *          buffer set the bounds of the copy
	 */
	public native void setByteBuffer(int index, ByteBuffer data);

	/**
	 * Peers this object with the supplied object. This object will be pointing at
	 * the same memory as the supplied object.
	 * 
	 * @param src
	 *          source object that holds the memory location and size this object
	 *          will point to
	 * @return size of the src and this object
	 */
	@Override
	public int peer(JMemory src) {
		return super.peer(src);
	}
}
