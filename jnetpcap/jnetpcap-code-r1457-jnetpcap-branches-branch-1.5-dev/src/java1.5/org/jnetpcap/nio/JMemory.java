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
import java.util.Properties;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PeeringException;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.util.Units;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;
import com.slytechs.library.LibraryMember;

/**
 * A base class for all other PEERED classes to native c structures. The class
 * only contains the physical address of the native C structure. The class also
 * contains a couple of convenience methods for allocating memory for the
 * structure to be peered as well as doing cleanup and freeing up that memory
 * when object is finalized().
 * <p>
 * This is one of the most important classes within jNetPcap library. It is
 * responsible for most of the memory allocation and management behind the
 * scenes of all jNetPcap native methods.
 * </p>
 * 
 * @since 1.2
 * @author Sly Technologies, Inc.
 */
@Library(preload = { JMemoryReference.class

}, natives = {
		"c",
		"msvcmrt",
		"msvcrt"
}, jni = Pcap.LIBRARY)
public abstract class JMemory {

	/**
	 * Used in special memory allocation. Allows the user to specify the type
	 * allocation required of this memory object.
	 * 
	 * @author Sly Technologies, Inc.
	 */
	public enum Type {
		/**
		 * Peered object is being created as a reference pointer and has no memory
		 * allocated on its own. It is expected that new object will be peered with
		 * Existing memory location. The same concept as a native memory pointer,
		 * think void * in C.
		 */
		POINTER
	}

	/**
	 * The maximum amount of direct memory we are allowed to allocate. When the
	 * limit is breached, we block the allocating thread and try to free up memory
	 * from any unused references (using DisposableGC class). If that fails and a
	 * timeout occurs on the blocked thread, an OutOfMemory exception is thrown.
	 * 
	 * @see #maxDirectMemory()
	 */
	private static long directMemory;

	/**
	 * A soft limit for the amount of direct memory we are allowed to allocate.
	 * When a soft memory limit is breached, the allocating thread is not blocked
	 * and continues to honor memory allocations, at the same time (using
	 * DisposableGC class), we kick off memory cleanup and try to free up memory.
	 * The key feature is that memory allocation does not stop, while forced
	 * cleaned up of released references is initiated.
	 * <p>
	 * If directMemorySoft == 0 or directMemorySoft == directMemory, this property
	 * is ignored and only the directMemory property and its algorithm is used.
	 * 
	 * @see #softDirectMemory()
	 */
	private static long directMemorySoft;

	/** Name of the native library that wraps around libpcap and extensions. */
	public static final String JNETPCAP_LIBRARY_NAME = "jnetpcap";
	/**
	 * The default maximum value for 'nio.mx' system property, if not set. The
	 * actual runtime default value for 'nio.mx' property is calculated to be the
	 * lower of either {@link #MAX_DIRECT_MEMORY_DEFAULT} constant or the value
	 * specified on the JVM command line using '-Xmx<size>' option.
	 */
	public static final long MAX_DIRECT_MEMORY_DEFAULT = 64 * Units.MEBIBYTE;

	/**
	 * Convenience constant that is synonym as JMemory.Type.POINTER. Since this
	 * type constant is used so often, it is made as a in-class constant to make
	 * it easier to access.
	 */
	public static final JMemory.Type POINTER = JMemory.Type.POINTER;

	/**
	 * Load the native library and initialize JNI method and class IDs.
	 */
	static {
		try {
			JNILibrary.register(JMemory.class);

			setMaxDirectMemorySize(maxDirectMemory());
			setSoftDirectMemorySize(softDirectMemory());

		} catch (Exception e) {
			System.err.println(e.getClass().getName() + ": "
					+ e.getLocalizedMessage());
			throw new ExceptionInInitializerError(e);
		}
	}

	/**
	 * Allocate0.
	 * 
	 * @param size
	 *          the size
	 * @return the long
	 */
	@LibraryMember("malloc")
	private synchronized static native long allocate0(int size);

	/**
	 * Returns how much native memory is available for allocation. This is a limit
	 * set by method {@link #setMaxDirectMemorySize(long)}.
	 * 
	 * @return the difference between maxDirectMemory and reservedDirectMemory
	 */
	public static native long availableDirectMemory();

	/**
	 * Initializes JNI ids.
	 */
	@LibraryInitializer
	private static native void initIDs();

	/**
	 * Returns the hard limit for the amount of memory native is allowed to
	 * allocate. The memory setting defaults to JVMs max memory which can be
	 * specified with JVM command line option '-Xmx&lt;size&gt;.Once the 'nio.mx'
	 * limit is reached, the allocating thread is blocked and a JVM GC request is
	 * issued. The allocating thread continues to wait, until sufficient minimum
	 * amount (Default: {@literal DisposableGC#MIN_MEMORY_RELEASE})of native
	 * memory was cleaned up or a timeout (Default:
	 * 
	 * @return the limit in number of bytes
	 *         {@literal DisposableGC#OUT_OF_MEMORY_TIMEOUT} ms) occurs.
	 *         <p>
	 *         This limit can be set at startup of the application using the
	 *         following system properties, which are checked in the order listed
	 *         below:
	 *         <ol>
	 *         <li><code>org.jnetsoft.nio.MaxDirectMemorySize</code>
	 *         <li><code>nio.MaxDirectMemorySize</code>
	 *         <li><code>org.jnetsoft.nio.mx</code>
	 *         <li><code>nio.mx</code>
	 *         </ol>
	 *         The different property names, from the most fully qualified to the
	 *         least, are provided to property name conflict resolution. For
	 *         convenience, it is recommended that the user choose the least
	 *         qualified property name to use. In the unlikely event that another
	 *         library within the same runtime application uses the same property
	 *         name, one of the more qualified (or longer) property names can be
	 *         used to resolve the conflict.
	 *         </p>
	 */

	public static long maxDirectMemory() {
		if (directMemory != 0) {
			return directMemory;
		}

		Properties p = System.getProperties();
		String s = p.getProperty("org.jnetsoft.nio.MaxDirectMemorySize");
		s = (s == null) ? p.getProperty("nio.MaxDirectMemorySize") : s;
		s = (s == null) ? p.getProperty("org.jnetsoft.nio.mx") : s;
		s = (s == null) ? p.getProperty("nio.mx") : s;

		if (s != null) {
			directMemory = parseSize(s); // process suffixes kb,mb,gb,tb
		}

		if (directMemory == 0) {
			directMemory = maxDirectoryMemoryDefault();
		}

		return directMemory;
	}

	/**
	 * Used to trigger garbage collector. The method is private, but invoked from
	 * JNI space.
	 */
	private static void maxDirectMemoryBreached() {
		DisposableGC.getDefault().invokeSystemGCAndWait();
	}

	/**
	 * Calculates the default value for max direct memory when 'nio.mx' system
	 * property is not given. The calculated value is the lower of either the
	 * constant {@link #MAX_DIRECT_MEMORY_DEFAULT} or '-Xmx' cmd option, if
	 * specified.
	 * <p>
	 * The reason for the complexity with this calculation and we just don't
	 * default to '-Xmx' or JVM default, is that JVM on 64-bit system defaults to
	 * 512Mb, which way too much to also reserve our nio use. Without this
	 * algorithm, the combined total on 64-bit system is 1Gb of memory.
	 * </p>
	 * 
	 * @return the runtime default value for direct memory
	 */
	private static long maxDirectoryMemoryDefault() {
		long max = Runtime.getRuntime().maxMemory();

		if (max > MAX_DIRECT_MEMORY_DEFAULT) {
			max = MAX_DIRECT_MEMORY_DEFAULT;
		}

		return max;
	}

	/**
	 * Parses the size.
	 * 
	 * @param v
	 *          the v
	 * @return the long
	 */
	static long parseSize(String v) {
		v = v.trim().toLowerCase();
		long multiplier = 1;

		if (v.endsWith("tb")) {
			multiplier = Units.TEBIBYTE;
			v = v.substring(0, v.length() - 2);

		} else if (v.endsWith("gb")) {
			multiplier = Units.GIGIBYTE;
			v = v.substring(0, v.length() - 2);

		} else if (v.endsWith("mb")) {
			multiplier = Units.MEBIBYTE;
			v = v.substring(0, v.length() - 2);

		} else if (v.endsWith("kb")) {
			multiplier = Units.KIBIBYTE;
			v = v.substring(0, v.length() - 2);
		}

		final long size = Long.parseLong(v) * multiplier;

		return size;
	}

	/**
	 * Returns how much native memory has be used so far.
	 * 
	 * @return amount of memory reserved/allocated at this moment
	 */
	public static native long reservedDirectMemory();

	/**
	 * Sets a hard limit for the amount of memory native is allowed to allocate.
	 * When the limit is reached, and a GC collection can free up no more memory,
	 * OutOfMemoryException is thrown by the allocate function.
	 * <p>
	 * jNetPcap keeps track of all memory allocated and freed. The following JVM
	 * options set the limits: <code>-Dnio.mx=_size_</code>
	 * </p>
	 * 
	 * 
	 * @param size
	 *          size in bytes
	 */
	private static native void setMaxDirectMemorySize(long size);

	/**
	 * Sets a soft limit for the amount of memory native is allowed to allocate.
	 * When the limit is reached, and a GC collection can is invoked but with out
	 * blocking and memory allocation continues until the hard limit is reached.
	 * <p>
	 * jNetPcap keeps track of all memory allocated and freed. The following JVM
	 * options set the limits: <code>-Dnio.ms=_size_</code>
	 * </p>
	 * 
	 * 
	 * @param size
	 *          size in bytes
	 */
	private static native void setSoftDirectMemorySize(long size);

	/**
	 * Returns the soft limit for native memory allocation. When the soft memory
	 * allocation limit is reached, memory continues to be allocated without
	 * interruption or blocking. At the same the a JVM GC request is issued to
	 * start collecting unused objects and potentially cleanup memory. The JVM GC
	 * request may be repeated while the current memory allocation is above this
	 * soft limit, but is limited to a minimum delay between consecutive JVM GC
	 * requests. This process continues until memory allocation falls below this
	 * soft limit or the hard 'nio.mx' limit is reached.
	 * <p>
	 * This limit can be set at startup of the application using the following
	 * system properties, which are checked in the order listed below:
	 * <ol>
	 * <li><code>org.jnetsoft.nio.SoftDirectMemorySize</code>
	 * <li><code>nio.SoftDirectMemorySize</code>
	 * <li><code>org.jnetsoft.nio.ms</code>
	 * <li><code>nio.ms</code>
	 * </ol>
	 * The different property names, from the most fully qualified to the least,
	 * are provided to property name conflict resolution. For convenience, it is
	 * recommended that the user choose the least qualified property name to use.
	 * In the unlikely event that another library within the same runtime
	 * application uses the same property name, one of the more qualified (or
	 * longer) property names can be used to resolve the conflict.
	 * </p>
	 * 
	 * @return the amount of memory, in bytes, before we start requesting a
	 *         forcible JVM GC.
	 */
	public static long softDirectMemory() {
		if (directMemorySoft != 0) {
			return directMemorySoft;
		}

		Properties p = System.getProperties();
		String s = p.getProperty("org.jnetsoft.nio.SoftDirectMemorySize");
		s = (s == null) ? p.getProperty("nio.SoftDirectMemorySize") : s;
		s = (s == null) ? p.getProperty("org.jnetsoft.nio.ms") : s;
		s = (s == null) ? p.getProperty("nio.ms") : s;

		if (s != null) {
			directMemorySoft = parseSize(s); // process suffixes kb,mb,gb,tb
		}

		if (directMemorySoft == 0) {
			directMemorySoft = maxDirectMemory();
		}

		return directMemorySoft;
	}

	/**
	 * Soft limit has been reached. Invoke non-blocking JVM GC and inject a marker
	 * reference. The marker reference will tell us when JVM GC reached the marker
	 * and thus, at a minimum has started processing unused references. The JVM GC
	 * can not be invoked more then once within a certain amount of time which is
	 * defined as {@value DisposableGC#MIN_SYSTEM_GC_INVOKE_TIMEOUT}.
	 */
	private static void softDirectMemoryBreached() {
		DisposableGC.getDefault().invokeSystemGCWithMarker();
	}

	/**
	 * Returns the total number of active native memory bytes currently allocated
	 * that have not been deallocated as of yet. This number can be calculated by
	 * the following formula:
	 * 
	 * <pre>
	 * totalAllocated() - totalDeAllocated()
	 * </pre>
	 * 
	 * @return number of native memory bytes still allocated
	 */
	public static long totalActiveAllocated() {
		return totalAllocated() - totalDeAllocated();
	}

	/**
	 * Returns total number of allocate calls through JMemory class. The memory is
	 * allocated by JMemory class using native "malloc" calls and is not normally
	 * reported by JRE memory usage.
	 * 
	 * @return total number of function calls made to malloc since JMemory class
	 *         was loaded into memory
	 */
	public native static long totalAllocateCalls();

	/**
	 * Returns total number of bytes allocated through JMemory class. The memory
	 * is allocated by JMemory class using native "malloc" calls and is not
	 * normally reported by JRE memory usage.
	 * 
	 * @return total number of bytes allocated since JMemory class was loaded into
	 *         memory
	 */
	public native static long totalAllocated();

	/**
	 * Returns the number of memory segments that were allocated by JMemory class
	 * in the range of 0 to 255 bytes in size. This is number of segments, not
	 * amount of memory allocated.
	 * 
	 * @return the total number of memory segments in this size
	 */
	public native static long totalAllocatedSegments0To255Bytes();

	/**
	 * Returns the number of memory segments that were allocated by JMemory class
	 * in the range of 256 bytes or above in size. This is number of segments, not
	 * amount of memory allocated.
	 * 
	 * @return the total number of memory segments in this size
	 */
	public native static long totalAllocatedSegments256OrAbove();

	/**
	 * Returns total number of deallocate calls through JMemory class. The memory
	 * is allocated by JMemory class using native "free" calls and is not normally
	 * reported by JRE memory usage.
	 * 
	 * @return total number of function calls made to free since JMemory class was
	 *         loaded into memory
	 */
	public native static long totalDeAllocateCalls();

	/**
	 * Returns total number of bytes deallocated through JMemory class. The memory
	 * is deallocated by JMemory class using native "free" calls and is not
	 * normally reported by JRE memory usage.
	 * 
	 * @return total number of bytes deallocated since JMemory class was loaded
	 *         into memory
	 */
	public native static long totalDeAllocated();

	/**
	 * Transfer to0.
	 * 
	 * @param address
	 *          the address
	 * @param buffer
	 *          the buffer
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	protected static native int transferTo0(long address,
			byte[] buffer,
			int srcOffset,
			int length,
			int dstOffset);

	/**
	 * Used to keep a reference tied with this memory object.
	 */
	private Object keeper = null;

	/**
	 * Specifies if this object owns the allocated memory. Using
	 * JMemory.allocate() automatically makes the object owner of the allocated
	 * memory block. Otherwise it is assumed that the {@link #physical} memory
	 * pointer is referencing a memory block not owned by this object, and
	 * therefore will not try and deallocate that memory upon cleanup.
	 * <p>
	 * Remember that physical field is set from within a native call and any
	 * object sub-classing JMemory can be made to reference any memory location
	 * including another JMemory object's allocated memory or anywhere for that
	 * matter.
	 * </p>
	 */
	private boolean owner = false;

	/**
	 * Physical address of the peered structure. This variable is modified outside
	 * java space as C structures are bound to it. Subclasses implement methods
	 * and fields that understand the exact structure.
	 */
	long physical;

	/** The ref. */
	private JMemoryReference ref = null;

	/** Number of byte currently allocated. */
	int size;

	/**
	 * Instantiates a new j memory.
	 * 
	 * @param peer
	 *          the peer
	 */
	public JMemory(ByteBuffer peer) {
		this(peer.limit() - peer.position());

		transferFrom(peer);
	}

	/**
	 * Pre-allocates memory for any structures the subclass may need to use.
	 * 
	 * @param size
	 *          number of bytes to pre-allocate allocate
	 */
	public JMemory(int size) {
		if (size <= 0) {
			throw new IllegalArgumentException("size must be greater than 0");
		}

		allocate(size);
	}

	/**
	 * Performs a deep copy into a newly allocated memory block.
	 * 
	 * @param src
	 *          the src
	 */
	public JMemory(JMemory src) {
		allocate(src.size);

		src.transferTo(this);
	}

	/**
	 * No memory pre-allocation constructor.
	 * 
	 * @param type
	 *          type of memory allocation model
	 */
	public JMemory(Type type) {
		if (type != Type.POINTER) {
			throw new IllegalArgumentException("Only POINTER types are supported");
		}
	}

	/**
	 * Method allocates native memory to hold the sub-classed C structure if the
	 * size is knows ahead of time. The physical field is set to the address of
	 * the allocated structure.
	 * 
	 * @param size
	 *          number of bytes to allocate.
	 * @return the long
	 */
	private long allocate(int size) {

		this.physical = allocate0(size);
		this.size = size;
		this.owner = true;
		this.keeper = this;

		this.ref = createReference(this.physical, size);

		return physical;
	}

	/**
	 * Checks if this peered object is initialized. This method throws
	 * IllegalStateException if not initialized and does not return any values.
	 * Its intended to as an assert mechanism
	 * 
	 * @throws IllegalStateException
	 *           if peered object is not initialized this unchecked exception will
	 *           be thrown, otherwise it will exit silently
	 */
	public void check() throws IllegalStateException {
		if (physical == 0) {
			throw new IllegalStateException(
					"peered object not synchronized with native structure");
		}
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
			throw new IndexOutOfBoundsException(
					String.format("index=%d, len=%d, size=%d", index, len, size));
		}

		return index;
	}

	/**
	 * Called to clean up and release any allocated memory. This method should be
	 * Overridden if the allocated memory is not simply a single memory block and
	 * something more complex. This method is safe to call at any time even if the
	 * object does not hold any allocated memory or is not the owner of the memory
	 * it is peered with. The method will reset this object to original un-peered
	 * state releasing any allocated and own memory at the same time if
	 * necessary.
	 */
	protected void cleanup() {
		if (ref != null) {
			this.ref.dispose();
			if (this.ref != null) {
				this.ref.remove();
			}
			this.ref = null;
		}
		this.owner = false;
		this.keeper = null;
		this.physical = 0L;
		this.size = 0;
	}

	/**
	 * Creates a cleanup/dispose weak reference object. This reference object is
	 * responsible for cleanup, after the actual JMemory object is garbage
	 * collected. After this object is garbage collected, the dispose method on
	 * the returned JMemoryReference object will be called at some point, when
	 * this object on longer exists, to cleanup. All JMemoryReferences contain a
	 * native memory pointer to the memory that potentially needs cleanup and
	 * disposal.
	 * <p>
	 * This method is protected and allows subclasses to provide their own cleanup
	 * code. If this method is not overridden, it will return a JMemoryReference
	 * object suitable to cleanup after this memory object.
	 * </p>
	 * 
	 * @param address
	 *          native memory address to use in the disposable
	 * @param size
	 *          the size
	 * @return a reference that is tied to this JMemory object
	 */
	protected JMemoryReference createReference(final long address, long size) {
		return new JMemoryReference(this, address, size);
	}

	/**
	 * Checks if this peered object is initialized. This method does not throw any
	 * exceptions.
	 * 
	 * @return if initialized true is returned, otherwise false
	 */
	public boolean isInitialized() {
		return physical != 0;
	}

	/**
	 * Checks if physical memory pointed to by this object, is owned either by
	 * this JMemory based object or the actual owner is also JMemory based. This
	 * method provides a check if the physical memory pointed to by this object
	 * has been allocated through use of one of JMemory based functions or outside
	 * its memory management scope. For example, memory allocated by libpcap
	 * library will return false. While packets that copied their state to new
	 * memory will return true.
	 * 
	 * @return true if physical memory is managed by JMemory, otherwise false
	 */
	public boolean isJMemoryBasedOwner() {
		return physical != 0 && (owner || keeper instanceof JMemory);
	}

	/**
	 * Checks if this object is the owner of native memory
	 * 
	 * @return true if this object is the owner, otherwise false
	 */
	public final boolean isOwner() {
		return this.owner;
	}

	/**
	 * Peers the src structure with this instance. The physical memory that the
	 * src peered object points to is set to this instance. The owner flag is not
	 * copied and src remains at the same state as it did before. This instance
	 * does not become the owner of the memory.
	 * <p>
	 * Further more, since we are peering with a ByteBuffer, the actual memory
	 * that is peered is between ByteBuffer's position and limit properties. Those
	 * 2 properties determine which portion of the memory that will be peered.
	 * This allows a larger ByteBuffer to be peered with different objects
	 * providing rudimentary memory allocation mechanism.
	 * </p>
	 * <p>
	 * Lastly care must be taken, to ensure that the life-spans do not conflict.
	 * The memory that we are peering to must not be deallocated prior the
	 * termination of the life-span of this object or at minimum calling
	 * 
	 * @param peer
	 *          The ByteBuffer whose allocated native memory we want to peer with.
	 *          The ByteByffer must be if direct buffer type which can be checked
	 *          using ByteBuffer.isDirect() call.
	 * @return the int
	 * @throws PeeringException
	 *           the peering exception {@link #cleanup()} method to ensure that
	 *           this object no longer references memory which may have been or
	 *           become deallocated.
	 *           </p>
	 * @see ByteBuffer#isDirect()
	 */
	protected native int peer(ByteBuffer peer) throws PeeringException;

	/**
	 * Peers the peer structure with this instance. The physical memory that the
	 * peer object points to is set to this instance. The owner flag is not copied
	 * and peer remains at the same state as it did before. This instance does not
	 * become the owner of the memory.
	 * 
	 * @param peer
	 *          the object whose allocated native memory we want to peer with
	 * @return the int
	 */
	protected int peer(JMemory peer) {
		return peer(peer, 0, peer.size);
	}

	/**
	 * Peers the peer structure with this instance. The physical memory that the
	 * peer object points to is set to this instance. The owner flag is not copied
	 * and peer remains at the same state as it did before. This instance does not
	 * become the owner of the memory. The function allows peering to a sub
	 * portion of the peer given the specified offset and length. The function
	 * strictly checks and enforces the bounds of the request to guarantee that
	 * peer is not allowed to access physical memory outside of actual peer range.
	 * 
	 * @param peer
	 *          object memory block to peer with
	 * @param offset
	 *          offset into the memory block
	 * @param length
	 *          amount of memory to peer with
	 * @return the int
	 * @throws IndexOutOfBoundsException
	 *           if the specified memory offset and length have negative or out of
	 *           bounds of peer objects address space
	 */
	protected int peer(JMemory peer, int offset, int length)
			throws IndexOutOfBoundsException {

		if (offset < 0 || length < 0 || offset + length > peer.size) {
			throw new IndexOutOfBoundsException("Invalid [" + offset + ","
					+ (offset + length) + "," + length + ") range.\n" + toDebugString());
		}

		return peer0(peer.physical + offset, length, peer.keeper);
	}

	/**
	 * Peers the peer structure with this instance. The physical memory that the
	 * peer object points to is set to this instance. The owner flag is not copied
	 * and peer remains at the same state as it did before. This instance does not
	 * become the owner of the memory. The function allows peering to a sub
	 * portion of the peer given the specified offset and length. The function
	 * strictly checks and inforces the bounds of the request to guarrantee that
	 * peer is not allowed to access physical memory outside of actual peer range.
	 * 
	 * @param peerAddress
	 *          the peer address
	 * @param length
	 *          amount of memory to peer with
	 * @param keeper
	 *          the keeper
	 * @return the int
	 * @throws IndexOutOfBoundsException
	 *           if the specified memory offset and length have negative or out of
	 *           bounds of peer objects address space
	 */
	private int peer0(long peerAddress, int length, Object keeper)
			throws IndexOutOfBoundsException {

		if (peerAddress != this.physical) {
			cleanup();
		}

		this.physical = peerAddress;
		this.size = length;

		/**
		 * For specific reasons, we can never be the owner of the peered structure.
		 * The owner should remain the object that initially created or was created
		 * to manage the physical memory. The reasons are as follows:
		 * <ul>
		 * <li>Memory could be a revolving buffer
		 * <li>Memory allocation could have been complex with sub structures that
		 * need to be deallocated
		 * <li>The src object may have been passed around and references stored to
		 * it elsewhere. If we are GCed before src and we free up the memory the
		 * original src object would become unstable
		 * </ul>
		 */

		this.keeper = keeper;

		return size;
	}

	/**
	 * Changes the size of the current memory buffer. The size can only be reduced
	 * in length and can not grow. The method throws exceptions if size parameter
	 * is greater then current size or negative.
	 * 
	 * @param size
	 *          size in bytes that is smaller then existing size
	 */
	public void setSize(int size) {
		if (size > this.size) {
			throw new IllegalArgumentException(
					String
							.format("size (%d) parameter must be less then buffer size (%d)",
									size,
									this.size));
		}

		if (size < 0) {
			throw new IllegalArgumentException("negative size parameter");
		}

		this.size = size;
	}

	/**
	 * Changes the size of the current memory buffer. This is a special private
	 * version of setSize which does not check the bounds. Often, in the scanner
	 * code, it is neccessary to resize JMemory peers up. This is possible since
	 * the JScanner native buffer knows its size and allows objects to be resized.
	 * 
	 * @param size
	 *          size in bytes
	 */
	private void setSize0(int size) {
		this.size = size;
	}

	/**
	 * Returns the size of the memory block that this peered structure is point
	 * to. This object does not neccessarily have to be the owner of the memory
	 * block and could simply be a portion of the over all memory block.
	 * 
	 * @return number of byte currently allocated
	 */
	public int size() {
		if (isInitialized() == false) {
			throw new NullPointerException("jmemory not initialized");
		}

		return size;
	}

	/**
	 * Returns a debug string about this JMemory state. Example:
	 * 
	 * <pre>
	 * JMemory@b052fa8: size=1506, owner=nio.JMemoryPool$Block.class(size=10240/offset=4064)
	 * </pre>
	 * 
	 * <ul>
	 * <li>hex nuber, is physical memory location
	 * <li>size = number of bytes of this memory object
	 * <li>owner = the class name of the object that owns the physical memory
	 * <li>isOwner = if true, means that this object is the owner of physical
	 * memory
	 * <li>size in parenthesis = the size of the physical memory allocated by the
	 * owner
	 * <li>offset in parenthesis = the offset into the physical memory block of
	 * this memory object
	 * </ul>
	 * 
	 * @return a summary string describing the state of this memory object
	 */
	public String toDebugString() {
		StringBuilder b = new StringBuilder();

		b.append("JMemory: JMemory@").append(Long.toHexString(physical))
				.append(getClass().toString()).append(": ");
		b.append("size=").append(size).append(" bytes");
		if (!owner) {
			b.append("\n");
			b.append("JMemory: owner=").append((keeper == null) ? "null" : keeper
					.getClass().getName().replaceAll("org.jnetpcap.", ""));
			b.append(".class");
			if (keeper instanceof JMemory) {
				JMemory k = (JMemory) keeper;
				b.append("(size=").append(k.size);
				b.append("/offset=").append(this.physical - k.physical);
				b.append(')');
			}
		} else {
			b.append("\n").append("JMemory: isOwner=").append(owner);
		}

		return b.toString();
	}

	/**
	 * A debug method, similar to toString() which converts the contents of the
	 * memory to textual hexdump.
	 * 
	 * @return multi-line hexdump of the entire memory region
	 */
	public String toHexdump() {
		JBuffer b = new JBuffer(Type.POINTER);
		b.peer(this);

		return FormatUtils.hexdumpCombined(b.getByteArray(0, size),
				0,
				0,
				true,
				true,
				true);
	}

	/**
	 * A debug method, similar to toString() which converts the contents of the
	 * memory to textual hexdump.
	 * 
	 * @param length
	 *          maximum number of bytes to dump to hex output
	 * @param address
	 *          flag if set to true will print out address offset on every line
	 * @param text
	 *          flag if set to true will print out a text characters at the end of
	 *          everyline
	 * @param data
	 *          flag if set to true will print out raw HEX data on every line
	 * @return multi-line hexdump of the entire memory region
	 */
	public String toHexdump(int length,
			boolean address,
			boolean text,
			boolean data) {
		length = (length < size) ? length : size;
		JBuffer b = new JBuffer(Type.POINTER);
		b.peer(this);

		return FormatUtils.hexdumpCombined(b.getByteArray(0, length),
				0,
				0,
				address,
				text,
				data);
	}

	/**
	 * Copies contents of byte array to memory.
	 * 
	 * @param buffer
	 *          source buffer
	 * @return number of bytes copied
	 */
	protected int transferFrom(byte[] buffer) {
		return transferFrom(buffer, 0, buffer.length, 0);
	}

	/**
	 * Copies contents of byte array to memory.
	 * 
	 * @param buffer
	 *          source buffer
	 * @param srcOffset
	 *          starting offset into the byte array
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          starting offset into memory buffer
	 * @return number of bytes copied
	 */
	protected native int transferFrom(byte[] buffer,
			int srcOffset,
			int length,
			int dstOffset);

	/**
	 * Copies data from memory from direct byte buffer to this memory.
	 * 
	 * @param src
	 *          source buffer
	 * @return actual number of bytes that was copied
	 */
	protected int transferFrom(ByteBuffer src) {
		return transferFrom(src, 0);
	}

	/**
	 * Copies data from memory from direct byte buffer to this memory.
	 * 
	 * @param src
	 *          source buffer
	 * @param dstOffset
	 *          offset into our memory location
	 * @return actual number of bytes that was copied
	 */
	protected int transferFrom(ByteBuffer src, int dstOffset) {
		if (src.isDirect()) {
			return transferFromDirect(src, dstOffset);
		} else {
			return transferFrom(src.array(),
					src.position(),
					src.limit() - src.position(),
					dstOffset);
		}
	}

	/**
	 * Copies data from memory from direct byte buffer to this memory.
	 * 
	 * @param src
	 *          source buffer
	 * @param dstOffset
	 *          offset into our memory location
	 * @return actual number of bytes that was copied
	 */
	protected native int transferFromDirect(ByteBuffer src, int dstOffset);

	/**
	 * A special method that allows one object to transfer ownership of a memory
	 * block. The supplied JMemory object must already be the owner of the memory
	 * block. This policy is strictly enforced. If the ownership transfer
	 * succeeds, this memory object will be responsible for freeing up memory
	 * block when this object is garbage collected or the user calls
	 * JMemory.cleanup() method. <h2>Warning!</h2> Care must be taken to only
	 * transfer ownership for simple memory allocations. If a complex memory
	 * allocation was used, one that sub allocates other memory blocks which are
	 * referenced from the original memory block, to avoid creating memory leaks.
	 * It is best practice to sub allocate other memory blocks using JMemory class
	 * which will properly manage that memory block and ensure that it will freed
	 * properly as well.
	 * 
	 * @param memory
	 *          memory block to transfer the ownership from
	 * @return if tranfer succeeded true is returned, otherwise false.
	 */
	protected boolean transferOwnership(JMemory memory) {
		if (!memory.owner || this.physical == 0 || this.physical != memory.physical) {
			return false;
		}

		memory.owner = false;
		this.owner = true;
		this.keeper = null; // Release any kept references

		if (this.ref != null) {
			throw new IllegalStateException(
					"Can not transfer ownership when already own memory");
		}
		this.ref = createReference(memory.ref.address, memory.ref.size);

		memory.ref.remove();
		memory.ref = null;

		return true;
	}

	/**
	 * Copies data from memory to byte array.
	 * 
	 * @param buffer
	 *          destination buffer starting offset in byte array
	 * @return number of bytes copied
	 */
	protected int transferTo(byte[] buffer) {

		return transferTo(buffer, 0, buffer.length, 0);
	}

	/**
	 * Copies data from memory to byte array.
	 * 
	 * @param buffer
	 *          destination buffer
	 * @param srcOffset
	 *          starting offset in memory
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          starting offset in byte array
	 * @return number of bytes copied
	 */
	protected int transferTo(byte[] buffer,
			int srcOffset,
			int length,
			int dstOffset) {

		if (buffer == null) {
			throw new NullPointerException();
		}

		if (dstOffset < 0 || dstOffset + length > buffer.length) {
			throw new ArrayIndexOutOfBoundsException();
		}

		return transferTo0(physical,
				buffer,
				check(srcOffset, length, physical),
				length,
				dstOffset);
	}

	/**
	 * Copies teh contents of this memory to buffer.
	 * 
	 * @param dst
	 *          destination buffer
	 * @return actual number of bytes that was copied
	 */
	public int transferTo(ByteBuffer dst) {
		return transferTo(dst, 0, size);
	}

	/**
	 * Copies teh contents of this memory to buffer.
	 * 
	 * @param dst
	 *          destination buffer
	 * @param srcOffset
	 *          offset in source
	 * @param length
	 *          number of bytes to copy
	 * @return number of bytes copied
	 */
	public int transferTo(ByteBuffer dst, int srcOffset, int length) {
		if (dst.isDirect()) {
			return transferToDirect(dst, srcOffset, length);
		} else {
			int o = transferTo(dst.array(), srcOffset, length, dst.position());
			dst.position(dst.position() + o);

			return o;
		}
	}

	/**
	 * Transfers the contents of this memory to buffer.
	 * 
	 * @param dst
	 *          destination buffer
	 * @param srcOffset
	 *          offset in source
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          offset in destination buffer
	 * @return number of bytes copied
	 */
	public int transferTo(JBuffer dst, int srcOffset, int length, int dstOffset) {
		return transferTo((JMemory) dst, srcOffset, length, dstOffset);
	}

	/**
	 * Copied the entire contents of this memory to destination memory.
	 * 
	 * @param dst
	 *          destination memory
	 * @return number of bytes copied
	 */
	protected int transferTo(JMemory dst) {
		return transferTo(dst, 0, size, 0);
	}

	/**
	 * Copied the entire contents of this memory to destination memory.
	 * 
	 * @param dst
	 *          destination memory
	 * @param srcOffset
	 *          offset in source
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          offset in destination buffer
	 * @return number of bytes copied
	 */
	protected native int transferTo(JMemory dst,
			int srcOffset,
			int length,
			int dstOffset);

	/**
	 * Transfer to direct.
	 * 
	 * @param dst
	 *          the dst
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @return actual number of bytes that was copied
	 */
	private native int transferToDirect(ByteBuffer dst, int srcOffset, int length);
}
