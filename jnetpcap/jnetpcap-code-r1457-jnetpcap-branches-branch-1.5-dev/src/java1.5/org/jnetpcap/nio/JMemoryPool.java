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

import java.nio.ByteBuffer;
import java.sql.Time;
import java.util.Properties;

import org.jnetpcap.nio.JMemory.Type;

/**
 * Provides a mechanism for allocating memory to JMemory objects. This class is
 * intended to be used when for example JPacket objects need to be kept around
 * for longer periods of time than a single loop cycle. Since libpcap library
 * utilizes a round-robin memory buffer for returning packet data buffers, this
 * class provides a mechanism for copying that data into more permanent storage
 * very efficiently.
 * <p>
 * The pool works by allocating a memory blocks which are given out to any
 * JMemory class that requests a chunk. That memory is given out, out of the
 * pool, until the block is completely exhausted, then a new block is allocated
 * and continues to give out the memory. The memory blocks are released and
 * deallocated when the last JMemory block that receive any of the memory is
 * garbage collected. When that happens the original memory block is deallocated
 * with a native C free() call. The user does not have to do anything special,
 * the memory management is done completely behind the scene, very efficiently
 * and automatically using java's garbage collection mechanism.
 * </p>
 * 
 * @author Sly Technologies, Inc.
 */
public class JMemoryPool {

	/**
	 * A block of native memory allocated with malloc. This block is further sub
	 * allocated on a per request basis using the method {@link #allocate(int)}.
	 * 
	 * @author Sly Technologies, Inc.
	 */
	public static class Block extends JMemory {

		/** How many bytes are available for allocation in this current block. */
		private int available = 0;

		/** Position into the block where the next available byte resides. */
		private int current = 0;

		/** The created on. */
		private final long createdOn;

		/**
		 * Constructor for allocating a block of a requested size.
		 * 
		 * @param size
		 *          number of bytes to allocate for this block
		 */
		Block(final int size) {
			super(size);
			this.available = size;
			this.createdOn = System.currentTimeMillis();
		}

		/**
		 * Peers this block with another memory object.
		 * 
		 * @param peer
		 *          memory object to peer with
		 */
		Block(final JMemory peer) {
			super(peer);
			this.createdOn = System.currentTimeMillis();
		}

		/**
		 * Allocates requested size number of bytes from existing memory block.
		 * 
		 * @param size
		 *          number of bytes
		 * @return offset into the buffer where the allocated memory begins
		 */
		public synchronized int allocate(int size) {

			/* Align to an even boundary */
			size += (size % BUS_WIDTH);

			if (size > this.available) {
				return -1;
			}
			final int allocated = this.current;
			this.available -= size;
			this.current += size;

			return allocated;
		}

		/**
		 * Frees the existing memory to be put back in the memory pool.
		 * 
		 * @param offset
		 *          the offset
		 * @param length
		 *          the length
		 */
		public void free(final int offset, final int length) {
			// Do nothing for now
		}

		/**
		 * To string.
		 * 
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			StringBuilder b = new StringBuilder(80);
			b.append("JMemoryPool::Block");
			b.append('[');
			b.append("capacity=").append(size());
			b.append(',');
			b.append("available=").append(this.current);
			b.append(',');
			b.append("createdOn=").append(new Time(this.createdOn).toString());
			b.append(']');

			return b.toString();
		}
	}

	/**
	 * The size of the native integer which is also the bus-size in bytes of the
	 * hardware architecture. We use the BUS_WIDTH to align our allocated memory
	 * on that boundary.
	 */
	private final static int BUS_WIDTH = JNumber.Type.INT.size;

	/**
	 * Default block size. JMemoryPool allocates memory in a large block which
	 * then further sub allocates per individual requests. The is the default
	 * size.
	 */
	public static final int DEFAULT_BLOCK_SIZE = 32 * 1024;

	/** The default pool. */
	private static JMemoryPool defaultPool;

	/**
	 * Allocates requested size of memory from the global memory pool.
	 * 
	 * @param size
	 *          allocation size in bytes
	 * @return buffer which references the allocated memory
	 */
	public static JBuffer buffer(final int size) {
		final JBuffer buffer = new JBuffer(Type.POINTER);
		defaultMemoryPool().allocate(size, buffer);

		return buffer;
	}

	/**
	 * Malloc.
	 * 
	 * @param size
	 *          the size
	 * @param storage
	 *          the storage
	 */
	public static void malloc(final int size, final JMemory storage) {
		defaultMemoryPool().allocate(size, storage);
	}

	/**
	 * Currently active block from which memory allocations take place if its big
	 * enough to fullfil the requests.
	 */
	private Block block;

	/**
	 * Current default block size when creating new memory blocks. This is user
	 * modifiable.
	 */
	private int blockSize;

	/**
	 * Uses default allocation size and strategy.
	 */
	public JMemoryPool() {
		blockSize = getBlockSize();
	}

	/**
	 * Allocates blocks in specified size.
	 * 
	 * @param defaultBlockSize
	 *          minimum memory block allocation size
	 */
	public JMemoryPool(final int defaultBlockSize) {
		this.blockSize = defaultBlockSize;
	}

	/**
	 * Allocates size bytes of memory and initializes the supplied memory pointer
	 * class.
	 * 
	 * @param size
	 *          number of bytes
	 * @param memory
	 *          memory pointer
	 */
	public synchronized void allocate(final int size, final JMemory memory) {

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		memory.peer(block, offset, size);
	}

	/**
	 * Allocates an exclusive block of native memory that once returned is not
	 * referenced by JMemoryPool.
	 * 
	 * @param size
	 *          amount of native memory to allocate in bytes
	 * @return object which is the owner of the allocated memory
	 */
	public JMemory allocateExclusive(final int size) {
		return new JMemory(size) {
			// Empty
		};
	}

	/**
	 * Transfers contents from src to newly allocated memory and peers dst with
	 * that the new memory. Any previously held resources by dst are freed.
	 * 
	 * @param src
	 *          source memory to copy from
	 * @param dst
	 *          destination object to peer with new memory containing copy of
	 *          memory pointed to by src
	 * @return number of bytes duplicated
	 */
	public synchronized int duplicate(JMemory src, JMemory dst) {
		final Block block = getBlock(src.size);
		final int offset = block.allocate(src.size);

		src.transferTo(block, 0, src.size, offset);
		dst.peer(block, offset, src.size);

		return src.size;
	}

	/**
	 * Transfers contents from src1 and src2 to a contiguous block of new memory,
	 * then peers dst1 and dst2 with the new memory, using the same sizes as src1
	 * and src2 respectively. This operation combines memory allocation,
	 * transferTo call on src1 and src2 and then peering of dst1 and dst2 with new
	 * memory in a single step.
	 * 
	 * @param src1
	 *          first src for duplicate
	 * @param src2
	 *          second src for duplicate into the same memory
	 * @param dst1
	 *          peered with new memory using src1 length
	 * @param dst2
	 *          peered with same memory at src1.length offset using src2 length as
	 *          length of peer
	 * @return total number of bytes duplicated
	 */
	public synchronized int duplicate2(JMemory src1,
			JMemory src2,
			JMemory dst1,
			JMemory dst2) {
		final int size1 = src1.size;
		final int size2 = src2.size;

		final int size = src1.size + src2.size;

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		int o = src1.transferTo(block, 0, size1, offset);
		src2.transferTo(block, 0, size2, offset + o);

		dst1.peer(block, offset, size1);
		dst2.peer(block, offset + o, size2);

		return size;
	}

	/**
	 * Transfers contents from src1 and src2 to a contigues block of new memory,
	 * then peers dst1 and dst2 with the new memory, using the same sizes as src1
	 * and src2 respectively. This operation combines memory allocation,
	 * transferTo call on src1 and src2 and then peering of dst1 and dst2 with new
	 * memory in a single step.
	 * 
	 * @param src1
	 *          first src for duplicate
	 * @param src2
	 *          second src for duplicate into the same memory
	 * @param dst1
	 *          peered with new memory using src1 length
	 * @param dst2
	 *          peered with same memory at src1.length offset using src2 length as
	 *          length of peer
	 * @return total number of bytes duplicated
	 */
	public synchronized int duplicate2(JMemory src1,
			ByteBuffer src2,
			JMemory dst1,
			JMemory dst2) {

		final int size1 = src1.size;
		final int size2 = src2.limit() - src2.position();

		final int size = size1 + size2;

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		int o = src1.transferTo(block, 0, size1, offset);
		block.transferFrom(src2, offset + o);

		dst1.peer(block, offset, size1);
		dst2.peer(block, offset + o, size2);

		return size;
	}

	/**
	 * Transfers contents from src to newly allocated memory and peers dst with
	 * that the new memory. Any previously held resources by dst are freed.
	 * 
	 * @param src
	 *          source memory to copy from
	 * @param dst
	 *          destination object to peer with new memory containing copy of
	 *          memory pointed to by src
	 * @return number of bytes duplicated
	 */
	public synchronized int duplicate(ByteBuffer src, JMemory dst) {

		final int size = src.limit() - src.position();

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		block.transferFrom(src, offset);

		dst.peer(block, offset, size);

		return size;
	}

	/**
	 * Gets a block of memory that is big enough to hold at least size number of
	 * bytes. The user must further request from the block
	 * 
	 * @param size
	 *          minimum available amount of memory in a block
	 * @return block big enough to hold size number of bytes
	 *         {@link Block#allocate(int)} the size of memory needed. The block
	 *         will then return an offset into the memory which has been reserved
	 *         for this allocation. The pool of used blocks with potential of some
	 *         available memory in them is maintained using a WeakReference. This
	 *         allows the blocks to be GCed when no references to them exist, even
	 *         if there is still a bit of available memory left in them.
	 * @see Block#allocate(int)
	 */
	public Block getBlock(int size) {

		/* Align to an even boundary */
		size += (size % BUS_WIDTH);

		if (this.block == null || this.block.available < size) {
			this.block = newBlock(size);
		}

		return this.block;
	}

	/**
	 * Creates a new block to be used for memory allocations of atLeast the size
	 * supplied or possibly bigger.
	 * 
	 * @param atLeastInSize
	 *          minimum number of bytes to allocate
	 * @return a new block to be used for allocations
	 */
	private Block newBlock(final int atLeastInSize) {
		return new Block((atLeastInSize > this.blockSize) ? atLeastInSize
				: this.blockSize);
	}

	/**
	 * Gets the global default memory pool.
	 * 
	 * @return the default pool
	 */
	public static JMemoryPool defaultMemoryPool() {
		if (defaultPool == null) {
			defaultPool = new JMemoryPool();
		}
		return defaultPool;
	}

	/**
	 * Shutdown.
	 */
	public static void shutdown() {
		if (defaultPool != null) {
			defaultPool.block = null;
			defaultPool = null;
		}
	}

	/**
	 * Gets the current default block size when creating new memory blocks.
	 * 
	 * @return the blockSize
	 */
	public int getBlockSize() {
		if (blockSize != 0) {
			return blockSize;
		}

		Properties p = System.getProperties();
		String s = p.getProperty("org.jnetsoft.nio.BlockSize");
		s = (s == null) ? p.getProperty("nio.BlockSize") : s;
		s = (s == null) ? p.getProperty("org.jnetsoft.nio.blocksize") : s;
		s = (s == null) ? p.getProperty("nio.blocksize") : s;
		s = (s == null) ? p.getProperty("nio.bs") : s;

		if (s != null) {
			blockSize = (int) JMemory.parseSize(s); // process suffixes kb,mb,gb,tb
		}

		if (blockSize == 0) {
			blockSize = DEFAULT_BLOCK_SIZE;
		}

		return blockSize;
	}

	/**
	 * Sets the current default block size when creating new memory blocks.
	 * 
	 * @param blockSize
	 *          the blockSize to set
	 */
	public void setBlockSize(int blockSize) {
		this.blockSize = blockSize;
	}

}
