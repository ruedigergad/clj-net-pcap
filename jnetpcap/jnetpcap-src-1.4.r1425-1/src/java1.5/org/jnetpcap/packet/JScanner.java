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

import org.jnetpcap.nio.JMemoryReference;
import org.jnetpcap.nio.JStruct;

// TODO: Auto-generated Javadoc
/**
 * JMemory with struct scanner_t, binding_t, packet_t and header_t structures.
 * JScanner utilizes unique numerical IDs assigned to each header to optimize
 * access and recording of information about the presence of each header in
 * various lookup array and bit masks. It also allocates a large memory block
 * natively and sub-allocates structures per packet and for each header. When
 * the end of the buffer is reached the buffer pointer is repositioned at the
 * beginning of the buffer and the memory block is reused, another words
 * round-robin algorithm is used over a single large buffer.
 * <p>
 * JScanner keeps a global jRegistry of header to ID mappings, bindings between
 * various headers and depedencies which are used to efficiently apply the
 * registered bindings. Further more, each JScanner instance can be customized
 * with a custom set of bindings and dependencies on a per instance basis. The
 * default is to use the global jRegistry. Therefore it is possible to override
 * certain bindings on a scanner basis such as overriding default binding for an
 * application level protocol to TCP port numbers for example.
 * </p>
 * <p>
 * The main scanner method is called <code>scan()</code>. This is a native
 * method that scans the contents of the supplied JBuffer which also contains
 * its data in native memory block typically allocated by libpcap, and records
 * the output of the scan into series of native structures and bitmaps. This
 * information is referenced by JPacket object. The JPacket memory pointer is
 * the only thing changed and thus a single JPacket object can very quickly be
 * repositioned to a new packet state.
 * </p>
 * 
 * <pre>
 * typedef struct header_t {
 *  int32_t hdr_id; // header ID
 *  int32_t hdr_offset; // offset into the packet_t-&gt;data buffer
 *  int32_t hdr_length; // length of the header in packet_t-&gt;data buffer
 * } header_t;
 * 
 * typedef struct packet_t {
 *  uint64_t pkt_header_map; // bit map of presence of headers
 * 
 *  // Keep track of how many instances of each header we have
 *  uint8_t pkt_instance_counts[MAX_ID_COUNT];
 *  char *pkt_data; // packet data buffer
 * 
 *  int32_t pkt_header_count; // total number of headers found
 *  header_t pkt_headers[]; // One per header + 1 more for payload
 *  } packet_t;
 * 
 *  typedef struct binding_t {
 *  int32_t bnd_id; // ID of the header that this binding is for
 *  // Map of required headers that must already processed in this packet
 *  uint64_t bnd_dependency_map;
 *  jobject bnd_jbinding; // JBinding object
 * } java_binding_t;
 * 
 * typedef struct scanner_t {
 *  int32_t sc_len; // bytes allocated for sc_packets buffer
 *  int32_t sc_offset; // offset into sc_packets for next packet
 * 
 *  // Cumulative map of dependencies that must already exist in the packet
 *  uint64_t sc_dependency_map[MAX_ID_COUNT];
 * 
 *  // Array of binding structures; The second array is NULL terminated 
 *  binding_t sc_bindings[MAX_ID_COUNT][MAX_BINDING_COUNT];
 * 
 *  uint64_t sc_binding_map; // bit mapping of java bindings 
 * 
 *  // Overrides CORE protocol bindings
 *  uint64_t sc_override_map[MAX_ID_COUNT];
 *  packet_t *sc_packet; // ptr into scanner_t where the first packet begins
 * } scanner_t;
 * 
 * </pre>
 * 
 * <p>
 * Note that a packet scanner (JScanner) is not a lightweight object but
 * actually fairely heavy to initialize and run. The scanner typically allocates
 * on the order of 100Kb of internal native memory for its state structures and
 * buffer. It is advisable to use its thread local getter methods which maintain
 * a pool of scanners on a per thread basis. Of course a new instance of a
 * scanner can be instantiated and configured differently from the default case
 * which uses the information in the global registry.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JScanner extends JStruct {

	/** The count. */
	private static int count = 0;

	/** Default allocation for memory block/buffer. */
	public static final int DEFAULT_BLOCKSIZE = 100 * 1024; // 100K

	/** The local scanners. */
	private static ThreadLocal<JScanner> localScanners =
			new ThreadLocal<JScanner>() {

				/*
				 * (non-Javadoc)
				 * 
				 * @see java.lang.ThreadLocal#initialValue()
				 */
				@Override
				protected JScanner initialValue() {
					return new JScanner();
				}

			};

	/** Maximum number of header entries allowed per packet buffer by the scanner. */
	public static final int MAX_ENTRY_COUNT = 64;

	/** Maximum number of ID entries allowed by the scanner. */
	public static final int MAX_ID_COUNT = 64;

	/** Name of the peered native structure. */
	public final static String STRUCT_NAME = "scanner_t";

	static {
		try {
			initIds();
		} catch (Exception e) {
			System.err.println("JScanner.static: error=" + e.toString());
			throw new ExceptionInInitializerError(e);
		}
	}

	/**
	 * Binding override.
	 * 
	 * @param id
	 *          the id
	 * @param enable
	 *          the enable
	 */
	public static void bindingOverride(int id, boolean enable) {
		if (enable) {
			JRegistry.setFlags(id, JRegistry.FLAG_OVERRIDE_BINDING);
		} else {
			JRegistry.clearFlags(id, JRegistry.FLAG_OVERRIDE_BINDING);
		}

		JPacket.getDefaultScanner().reloadAll();
	}

	/**
	 * Maintains and allocates a pool of packet scanners.
	 * 
	 * @return a thread local global scanner
	 */
	public static JScanner getThreadLocal() {
		// JScanner s = localScanners.get();
		// s.reloadAll();

		JScanner s = JPacket.getDefaultScanner();
		return s;
	}

	/**
	 * Shutdown.
	 */
	public static void shutdown() {

		localScanners.remove();
		localScanners = null;
	}

	/**
	 * Heuristic check.
	 * 
	 * @param id
	 *          the id
	 * @param enable
	 *          the enable
	 */
	public static void heuristicCheck(int id, boolean enable) {
		if (enable) {
			JRegistry.setFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
		} else {
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
		}

		JPacket.getDefaultScanner().reloadAll();
	}

	/**
	 * Heuristic post check.
	 * 
	 * @param id
	 *          the id
	 * @param enable
	 *          the enable
	 */
	public static void heuristicPostCheck(int id, boolean enable) {
		if (enable) {
			JRegistry.setFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_PRE_BINDING);
		} else {
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_PRE_BINDING);
		}

		JPacket.getDefaultScanner().reloadAll();
	}

	/**
	 * Heuristic pre check.
	 * 
	 * @param id
	 *          the id
	 * @param enable
	 *          the enable
	 */
	public static void heuristicPreCheck(int id, boolean enable) {
		if (enable) {
			JRegistry.setFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
			JRegistry.setFlags(id, JRegistry.FLAG_HEURISTIC_PRE_BINDING);
		} else {
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_PRE_BINDING);
		}

		JPacket.getDefaultScanner().reloadAll();
	}

	/**
	 * Initialized JNI method and fields IDs.
	 */
	private native static void initIds();

	/**
	 * Reset to defaults.
	 */
	public static void resetToDefaults() {
		for (int id = 0; id < JRegistry.MAX_ID_COUNT; id++) {
			JRegistry.clearFlags(id, 0xFFFFFFFF);
		}
	}

	/**
	 * Size of the entire scanner_t structure. Does not include the entire
	 * allocated memory block managed by this object.
	 * 
	 * @return result from sizeof(scanner_t) statement
	 */
	native static int sizeof();

	/**
	 * To bit mask.
	 * 
	 * @param ids
	 *          the ids
	 * @return the long
	 */
	private static long toBitMask(int... ids) {
		long o = 0L;
		for (int i = 0; i < ids.length; i++) {
			o |= (1L << i);
		}

		return o;
	}

	/**
	 * Allocates a default scanner using {@literal #DEFAULT_BLOCKSIZE} buffer
	 * size.
	 */
	public JScanner() {
		this(DEFAULT_BLOCKSIZE);

		/*
		 * List<StackTraceElement> list = new
		 * ArrayList<StackTraceElement>(Arrays.asList(Thread.currentThread()
		 * .getStackTrace())); list.remove(0); list.remove(0);
		 * System.out.printf("%s:%s%n", toString(), list);
		 */
	}

	/**
	 * Allocates the requested blocksize of memory + the sizeof(scanner_t).
	 * 
	 * @param blocksize
	 *          the blocksize
	 */
	public JScanner(int blocksize) {
		super(STRUCT_NAME + "#" + count++, blocksize + sizeof()); // Allocate memory

		init(new JScan());
		reloadAll();

		/*
		 * List<StackTraceElement> list = new
		 * ArrayList<StackTraceElement>(Arrays.asList(Thread.currentThread()
		 * .getStackTrace())); list.remove(0); list.remove(0);
		 * System.out.printf("%s:%s%n", toString(), list);
		 */
	}

	/**
	 * Retrieves the current frame number assigned by this scanner.
	 * 
	 * @return current frame counter value
	 */
	public native long getFrameNumber();

	/**
	 * Initializes the scanner_t structure within the allocated block.
	 * 
	 * @param scan
	 *          a uninitialized JScan object to be used internally by JScanner for
	 *          its interaction with java space.
	 */
	private native void init(JScan scan);

	/**
	 * Downloads flags for each protocol to the scanner's native implementation.
	 * 
	 * @param flags
	 *          array of flags, one for each protocol ID
	 */
	private native void loadFlags(int[] flags);

	/**
	 * Load scanners.
	 * 
	 * @param scanners
	 *          the scanners
	 */
	private native void loadScanners(JHeaderScanner[] scanners);

	/**
	 * Reloads the scanner and bindings table from JRegistry down to native
	 * scanner structures.
	 */
	public void reloadAll() {
		JHeaderScanner[] scanners = JRegistry.getHeaderScanners();

		for (int i = 0; i < scanners.length; i++) {
			if (scanners[i] == null) {
				continue;
			}

			if (scanners[i].hasBindings() || scanners[i].hasScanMethod()
					|| scanners[i].isDirect() == false) {
				// System.out.printf("%s, Downloading scanner [%s]\n", this,
				// scanners[i]);
			} else {
				scanners[i] = null;
			}
		}

		loadScanners(scanners);

		int[] flags = JRegistry.getAllFlags();
		loadFlags(flags);
	}

	/**
	 * Performs a scan on a packet that has been peered with a packet data buffer.
	 * The state structure o the packet is filled in and peered at the time of the
	 * packet scan.
	 * 
	 * @param packet
	 *          packet to process
	 * @param id
	 *          numerical ID of the data link protocol, or first header within the
	 *          data buffer
	 * @return number of bytes processed
	 */
	public int scan(JPacket packet, int id) {
		return scan(packet, id, packet.getPacketWirelen());
	}

	/**
	 * Performs a scan on a packet that has been peered with a packet data buffer.
	 * The state structure o the packet is filled in and peered at the time of the
	 * packet scan.
	 * 
	 * @param packet
	 *          packet to process
	 * @param id
	 *          numerical ID of the data link protocol, or first header within the
	 *          data buffer
	 * @param wirelen
	 *          original packet length
	 * @return number of bytes processed
	 */
	public int scan(JPacket packet, int id, int wirelen) {
		final JPacket.State state = packet.getState();

		return scan(packet, state, id, wirelen);
	}

	/**
	 * Performs the actual scan.
	 * 
	 * @param packet
	 *          packet to scan
	 * @param state
	 *          the state
	 * @param id
	 *          id of dlt protocol
	 * @param wirelen
	 *          the wirelen
	 * @return number of bytes processed
	 */
	private native int scan(JPacket packet,
			JPacket.State state,
			int id,
			int wirelen);

	/**
	 * Sets the scanner's current frame number to user specified value. This
	 * allows scanner's frame numbers it assigns and keeps track of to be reset
	 * back to 0 or some other value if needed.
	 * 
	 * @param frameNo
	 *          new frame number
	 */
	public native void setFrameNumber(long frameNo);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JMemory#createReference(long)
	 */
	/**
	 * Creates the reference.
	 * 
	 * @param address
	 *          the address
	 * @param size
	 *          the size
	 * @return the j memory reference
	 * @see org.jnetpcap.nio.JMemory#createReference(long, long)
	 */
	@Override
	protected JMemoryReference createReference(long address, long size) {
		return new JScannerReference(this, address, size);
	}
}
