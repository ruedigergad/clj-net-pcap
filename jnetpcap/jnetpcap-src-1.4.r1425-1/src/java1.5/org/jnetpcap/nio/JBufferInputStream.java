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

import java.io.IOException;
import java.io.InputStream;

// TODO: Auto-generated Javadoc
/**
 * IO InputStream class that reads data out of a JBuffer. This implementation
 * supports all methods efficiently, including bulk transfers and the optional
 * mark operation.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JBufferInputStream
    extends
    InputStream {

	/** The in. */
	private final JBuffer in;

	/** The position. */
	private int position;

	/** The end. */
	private final int end;

	/** The mark. */
	private int mark = -1;

	/**
	 * Creates a new input stream initialized to read data out of the supplied
	 * buffer.
	 * 
	 * @param in
	 *          source buffer to read data out of
	 */
	public JBufferInputStream(JBuffer in) {
		this(in, 0, in.size());
	}

	/**
	 * Creates a new input stream initialized to read data out fo the supplied
	 * buffer.
	 * 
	 * @param in
	 *          source buffer to read data out of
	 * @param offset
	 *          offset into the source buffer where to start reading
	 * @param length
	 *          number of byte to read out of the buffer before signalining end of
	 *          stream
	 */
	public JBufferInputStream(JBuffer in, int offset, int length) {
		/*
		 * Make sure the requested length is not bigger then our buffer. We can't
		 * use max(), because position and end haven't been initialized yet
		 */
		length = (offset + length > in.size()) ? in.size() - offset : length;

		this.in = in;
		this.position = offset;
		this.end = offset + length;
	}

	/**
	 * Reads 1 byte out of the underlying source buffer.
	 * 
	 * @return byte value read out of the buffer
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 * @see java.io.InputStream#read()
	 */
	@Override
	public int read() throws IOException {
		if (position == end) {
			return -1;
		}

		return in.getUByte(position++);
	}

	/**
	 * Number of bytes available for reading out of the buffer.
	 * 
	 * @return number of byte available in the buffer which is usually the entire
	 *         buffer
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	@Override
	public int available() throws IOException {
		return end - position;
	}

	/**
	 * Closes this input stream.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 * @see java.io.InputStream#close()
	 */
	@Override
	public void close() throws IOException {
		position = end;
	}

	/**
	 * Reads a block of data out of the source buffer.
	 * 
	 * @param b
	 *          buffer to store the block of data read
	 * @param off
	 *          offset into the destination buffer where to store the block data
	 * @param len
	 *          number of bytes to read as a block
	 * @return the int
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		final int length = max(len);

		in.getByteArray(position, b, off, length);

		return length;
	}

	/**
	 * Reads a block of data out of the source buffer.
	 * 
	 * @param b
	 *          Buffer to store the block of data read. The length of read
	 *          operation is the size of the byte array.
	 * @return the int
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	/**
	 * Advances the position with the source buffer effectively skipping over
	 * specified number of bytes.
	 * 
	 * @param n
	 *          of bytes to skip over
	 * @return actual number of bytes skipped over. Can be less then requested if
	 *         remaining number of bytes still to be read out of the source buffer
	 *         was less then requested
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	@Override
	public long skip(long n) throws IOException {
		long length = max((int) n);
		position += max((int) n);

		return length;
	}

	/**
	 * Sets a mark within the buffer where subsequent reset operation will revert
	 * back the position to.
	 * 
	 * @param readlimit
	 *          Maximum number of bytes expected to be read. This parameter is
	 *          ignored for source buffer operations since data does not need to
	 *          be buffered.
	 */
	@Override
	public synchronized void mark(int readlimit) {
		this.mark = position;
	}

	/**
	 * Checks if mark method is supported on this stream.
	 * 
	 * @return this method always returns true for this object type
	 */
	@Override
	public boolean markSupported() {
		return true;
	}

	/**
	 * Resets the stream back to position where it was previously marked.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	@Override
	public synchronized void reset() throws IOException {
		if (mark != -1) {
			position = mark;
			mark = -1;
		}
	}

	/**
	 * Calculate the maximum length that can be read out of the buffer based on
	 * the length requested. If the requested length is greater then what can be
	 * read out of the buffer, then this method returns just the available length.
	 * 
	 * @param len
	 *          checks if len bytes are aviable for reading
	 * @return number of bytes available for reading, upto the maximum of the
	 *         length requested
	 */
	private int max(int len) {
		final int available = end - position;
		final int max = (len > available) ? available : len;

		return max;
	}
}
