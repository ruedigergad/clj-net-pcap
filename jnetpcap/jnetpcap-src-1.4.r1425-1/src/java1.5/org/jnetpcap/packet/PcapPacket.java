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

import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemoryPool;

// TODO: Auto-generated Javadoc
/**
 * A pcap packet. Fully decoded packet that provides access to protocol headers
 * as determined during the decoding process. A <code>PcapPacket</code> class is
 * designed to work with pcap library. It can not be used to create a new packet
 * from an external memory buffer that only contains packet data, such as
 * preparing a packet to be sent from a network interface. You can use
 * <code>JMemoryPacket</code> to create an in memory packet from scratch.
 * PcapPackets need a PcapHeader which is provided by libpcap at the time the
 * packet was captured. Also the PcapPacket contains decoded state information
 * which can be used to query the packet for its contents using friendly java
 * API and compile-time type-safety. <h2>Packet accessors</h2> Once a decoded
 * packet is received, the user can query the packet for its various properties.
 * The most important of which is the existance of any particular protocol
 * header within the packet data buffer. The data buffer is scanned and decoded.
 * Any discovery of a protocol header within, is recorded in packet's state. The
 * following accessors can be used to query if a particular header has been
 * found within a packet:
 * <ul>
 * <li> <code>JPacket.hasHeader(int id):boolean</code> - id is the numerical
 * protocol ID assigned to each header type by JRegistry. The accessor returns a
 * boolean true or false if the header exists within the packet.</li>
 * <li>
 * <code>JPacket.getHeader(&lt;? extends JHeader&gt; header): &lt;? extends JHeader&gt;</code>
 * - an accessor that retrieves a specific instance of a header. A user supplied
 * instance of a protocol header is used, initialized to point at the
 * appropriate memory location within the data buffer, where the protocol
 * header's state and contents reside.</li>
 * <li>
 * <code>JPacket.hasHeader(<&lt;? extends JHeader&gt; header): boolean</code> -
 * a convenience accessor that combines hasHeader and getHeader methods into
 * one. If the header is found within the packet, boolean true is returned and
 * at the same time the user supplied instance of the header is initialized to
 * pointer at the header. Otherwise false is returned.</li>
 * </ul>
 * <p>
 * Here is an example of how to use an accessor form a PcapPacketHandler:
 * 
 * <pre>
 * public void nextPacket(PcapPacket packet, Object user) {
 * 	if (packet.hasHeader(Ethernet.ID)) {
 * 		Ethernet eth = packet.getHeader(new Ethernet());
 * 
 * 		System.out.printf(&quot;ethernet.type=%X\n&quot;, eth.type());
 * 	}
 * }
 * </pre>
 * 
 * Or more conveniently, combine hasHeader and getHeader in a single call
 * 
 * <pre>
 * private Ethernet eth = new Ethernet(); // Preallocate our ethernet header
 * 
 * private Ip4 ip = new Ip4(); // Preallocat IP version 4 header
 * 
 * public void nextPacket(PcapPacket packet, Object user) {
 * 	if (packet.hasHeader(eth)) {
 * 		System.out.printf(&quot;ethernet.type=%X\n&quot;, eth.type());
 * 	}
 * 
 * 	if (packet.hasHeader(ip)) {
 * 		System.out.println(&quot;ip.version=%d\n&quot;, ip.version());
 * 	}
 * }
 * </pre>
 * 
 * <h3>Accessing a subheader such as ip options</h3>
 * You can also access sub headers, usually supplied as options by the protocol
 * during transmission.
 * 
 * <pre>
 * private Ip4 ip = new Ip4(); // Preallocat IP version 4 header
 * private Ip4.Timestamp timestamp = new Ip4.Timestamp(); // Optional header
 * 
 * public void nextPacket(PcapPacket packet, Object user) {
 *  if (packet.hasHeader(ip) &amp;&amp; ip.hasSubHeader(timestamp)) {
 *    System.out.println(&quot;ip.version=%d\n&quot;, ip.version);
 *    System.out.println(&quot;timestamp optional header length=%d\n&quot;, timstamp.length());
 *  }
 * </pre>
 * 
 * A couple of points about the sub header example. Notice that we preallocated
 * a Timestamp header, which is defined from within Ip4 class itself, but is a
 * separate class on its own none the less. Next we first check if Ip4 header is
 * present at all in the packet, peer it if exists (combined hasHeader and
 * getHeader accessor method) and as a second step we check with the Ip4 header
 * if it has an optional header using <code>ip.hasSubHeader(timestamp)</code>.
 * If the method returns true, it also peers the sub header timestamp with the
 * appropriate packet data buffer where the optional header resides.
 * <h3>Formatting packet for output</h3>
 * A packet can easily be formatted for textual output. Any supported formatter,
 * such as TextFormatter or XmlFormatter can be used to format a packet for
 * output. Also JPacket.toString() method uses an internal StringBuilder based
 * TextFormatter that formats the packet for textual output in a string buffer.
 * At this time both ip and timestamp header instances are properly intialized
 * and can be used to access their respective headers.
 * 
 * <pre>
 * JPacket packet = // From out handler
 * TextFormatter out = new TextFormatter(System.out);
 * 
 * out.format(packet); // Send pretty output to stdout
 * 
 * // Or save time
 * System.out.println(packet.toString()); // Use internal TextFormatter
 * </pre>
 * 
 * </p>
 * <h2>Packet's lifecycle</h2> A PcapPacket is made up of 3 parts:
 * <ul>
 * <li>Packet data buffer - peered with packet object itself</li>
 * <li>Packet state - peered with packet state object</li>
 * <li>PcapCapture header - peered with packet header object</li>
 * </ul>
 * <p>
 * Each part of the packet is managed independently, that is either part can be
 * initialized or not. Either part can point to any memory location, including a
 * large single buffer of contigues bytes that contains all 3 parts, header,
 * state and packet data. There are various methods supplied by PcapPacket that
 * allow an external buffer to be peered with all 3 parts of the packet. There
 * are also many methods for transfering (deep copy) the data to and from
 * buffers.
 * </p>
 * <p>
 * All of these components are stored in native memory in native C structures
 * that are peered with the packet API classes. The classes, managed by
 * <code>JMemory</code> class are referencing native memory locations. Any
 * native method that is called upon in the PcapPacket class or its base
 * classes, will perform those operations on the peered structure and data.
 * </p>
 * When a packet is delivered from either Pcap.loop or Pcap.dispatch methods,
 * the capture header, packet state and packet data all point to different
 * unrelated memory locations. That is, capture header is peered with the
 * libpcap supplied pcap_pkthdr structure, Packet data buffer (the packet
 * itself) is peered with the data buffer supplied by pcap and the packet state
 * is peered with its packet_state_t structure as supplied by the JScanner,
 * typically out of its internal buffer. None of these default memory locations
 * are persistent for very long time. Both libpcap and JScanner buffers are
 * round robin buffers that eventually wrap around and reuse previously
 * dispatched memory.
 * <p>
 * These temporary packets are only suitable for immediate use. That is if the
 * packets are processed immediately when received and then discarded, they do
 * not need to be preserved. If a packet is to be put on a queue and for later
 * processing, the packet needs to preserve its state. That requires a physical
 * copy of all 3 components of the packet to a new memory location. The most
 * efficient way to store the new packet is to allocate a memory buffer large
 * enough to hold all of the packets state and data out of a JMemoryPool. The
 * JPacket provides a default singleton memory pool out of which all packets
 * allocate memory out of for the required space.
 * </p>
 * <h2>Advanced topiccs</h2> Below are several sections that describe the
 * lifecycle of a packet in more depth. For simply usage, the termporary packets
 * can be used immediately in the handler and then the packets can be discarded.
 * For more advanced usage lets go into the detail of how packet data can be
 * copied, preserved and peered to one another. <h3>Perserving packet's state
 * and data</h3> In order to preserve packet's state and data a deep copy needs
 * to be performed of all 3 components of he packet. PcapPacket class provides
 * several <code>PcapPacket.transferTo</code> methods that perform deep copies
 * of the packet. For efficiency reasons, each transferTo method are designed to
 * copy data into a memory buffer of larger size. The packet state and data are
 * copied to the buffer with the following layout within the buffer:
 * 
 * <pre>
 * +----------+-----+----+
 * |PcapHeader|State|Data|
 * +----------+-----+----+
 * </pre>
 * 
 * <p>
 * The buffer to which this copy takes place can be an external buffer or an
 * internally allocated one by the packet class itself. As stated before,
 * packet's use an interal singleton memory pool to allocate memory out of more
 * efficiently. This memory allocates large native memory blocks which are then
 * sub divided further and given out by the memory pool on a per request basis.
 * All the copies are done natively by low level native copy routines, not in
 * java space for maximum performace.
 * </p>
 * <p>
 * The easiest way to copy packet contents as received, for example, from
 * <code>PcapPacketHandler</code>, is to pass the temporary packet to the
 * PcapPacket constructor which will automatically allocate new space for the
 * packet state and data and perform a deep copy. The new packet immediately
 * becomes usable and is permanently stored in memory with its state and data,
 * until garbage collected. Here is an example of a PcapPacketHandler that
 * copies the temporary packet to new permanent one:
 * 
 * <pre>
 * pulic void nextPacket(PcapPacket packet, Queue&lt;PcapPacket&gt; queue) {
 *   PcapPacket permanent = new PcapPacket(packet);  
 *   queue.offer(permanent); 
 * }
 * </pre>
 * 
 * </p>
 * <p>
 * </p>
 * <p>
 * Alternative is to reused another packet and transfer the temporary packets
 * state and data to it or create a new unitiatialized packet with
 * <code>new PcapPacket(JMemory.Type.POINTER)</code> constructor and
 * subsequently perform <code>PcapPacket.transferTo(PcapPacket)</code> call to
 * copy the contents. In the first case where an existing packet is being
 * reused, if that packet already contains a large enough memory buffer to hold
 * the state and data of the temporary packet, that buffer is reused. Otherwise
 * a new buffer is allocated out of the default memory pool. Here is an exmaple:
 * *
 * 
 * <pre>
 * 
 * final PcapPacket permanent = new PcapPacket(Type.POINTER);
 * 
 * pulic void nextPacket(PcapPacket packet, Queue&lt;PcapPacket&gt; queue) {
 *   permanent.transferStateAndData(packet); 
 *   // Or
 *   packet.transferTo(permanent);
 * }
 * </pre>
 * 
 * In either case, any existing buffer previously allocated in the permanent
 * packet if its big enough to hold the state and data of the packet, is reused,
 * saving time on memory allocation. You can also manually allocate a large
 * buffer and reuse a packet:
 * 
 * <pre>
 * 
 * final PcapPacket permanent = new PcapPacket(64 * 1024); // Preallocate 64K
 * 
 * pulic void nextPacket(PcapPacket packet, Queue&lt;PcapPacket&gt; queue) {
 *   permanent.transferStateAndData(packet); 
 *   // Or
 *   packet.transferTo(permanent);
 * }
 * </pre>
 * 
 * In this example, the packet buffer will always be large enough and resused.
 * But still this is a semi permanentn state.
 * </p>
 * <p>
 * Yet another alternative is to store the contents of the packet in an external
 * buffer such as ByteBuffer, JBuffer or simply a byte[] and then at an
 * appropriate time, transfer the data back or peer the external buffer with a
 * packet object. Only the byte[] buffer type and ByteBuffer backed by a byte
 * array, can not be peered directly with a packet as only buffer sources that
 * are native memory based can be peered. All external buffer types can be
 * copied back into a packet, if peering is not required. New memory space is
 * allocated for the copy. Here is an example:
 * 
 * <pre>
 * pulic void nextPacket(PcapPacket packet, Queue&lt;PcapPacket&gt; queue) {
 *   JBuffer jbuf = new JBuffer(packet.getTotalSize());
 *   packet.transferTo(jbuf);
 *   // Or
 *   ByteBuffer bbuf = ByteBuffer.allocateDirect(packet.getTotalSize());
 *   packet.transferTo(bbuf);
 *   // Or
 *   byte[] babuf = new byte[packet.getTotalSize())];
 *   packet.transferTo(babuf);
 * }
 * </pre>
 * 
 * In all 3 cases, complete the packet's state and data buffer are copied to
 * external buffer.
 * </p>
 * <h2>Initializing packet from an external buffer</h2> Packet state and data
 * can be preseved in an external buffer large enough to hold the entire packet
 * with its state. PcapPacket class provides transferStateAndData and peer
 * methods that allow the external packet data to be either copied into a packet
 * or the packet be peered directly with the external buffer. Peering does not
 * need to allocate memory to hold the packet state, but its state and data are
 * directly read out of the extern buffer. If you change the contents of the
 * external buffer, the packet's state and data will change as well. Care must
 * be take with a direct reference to an external buffer, as its easy to
 * override sensitive data causing the packet to behave wildly and unexpectidly.
 * <code>JMemory</code> class prevents buffer overrun attacks and any access to
 * memory that has not been allocated. a direct reference. Here is an example:
 * 
 * <pre>
 * pulic void nextPacket(PcapPacket packet, Queue&lt;PcapPacket&gt; queue) {
 *   JBuffer jbuf = new JBuffer(packet.getTotalSize());
 *   packet.transferTo(jbuf);
 *   // Or
 *   ByteBuffer bbuf = ByteBuffer.allocateDirect(packet.getTotalSize());
 *   packet.transferTo(bbuf);
 *   // Or
 *   byte[] babuf = new byte[packet.getTotalSize())];
 *   packet.transferTo(babuf);
 *   
 *   PcapPacket p1 = new PcapPacket(jbuf); // Deep copy
 *   
 *   PcapPacket p2 = new PcapPacket(Type.POINTER); // Uninitialized
 *   bbuf.flip(); // Have to flip the buffer to access the just written contents
 *   p2.peer(bbuf); // No copies, peered directly with external buffer
 *   
 *   PcapPacket p3 = new PcapPacket(Type.POINTER); // Uninitialized
 *   p3.transferStateAndData(babuf); // Deep copy - byte[] buffers can not be peered
 *   
 *   PcapPacket p4 = new PcapPacket(Type.POINTER); // Uninitialized
 *   p4.peer(p3); // both point at same internal memory space
 * }
 * </pre>
 * 
 * The above example demonstrates 3 different ways that data from an external
 * buffer can be either copied or peered with a new packet object. In all cases
 * the data and state were transfered from the temporary packet received by the
 * handler to a more permenant buffer and then packet. An interesting scenerio
 * occures with packet p4. Lets take a closer look.
 * <p>
 * First, p3 is created unitialized, meaning that packet header, state and data
 * are null pointers at this time, they don't point to anything and any accessor
 * method used will immediately throw a NullPointerException. Second, the byte[]
 * external buffer is copied into newly allocate memory space by p3. The packet
 * is intiailized to pointer at its internal buffer for the header, state and
 * packet data. Then we create p4, also unitialized and in the following step we
 * peer p4 to p3. That is p4 points at the exact same memory location for
 * packet's header, state and data. No new memory was allocated and changing the
 * contents in either packet, p3 or p4, will have immediate effect on the other
 * packet. Another words, both p3 and p4 are peered to the same internal memory
 * space.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @see JMemoryPool
 */
public class PcapPacket extends JPacket {

	/** The Constant STATE_SIZE. */
	private final static int STATE_SIZE = PcapHeader.sizeof()
			+ JPacket.State.sizeof(DEFAULT_STATE_HEADER_COUNT);

	/**
	 * 
	 */
	static {
		try {
			initIds();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * JNI Ids.
	 */
	private native static void initIds();

	/** The header. */
	private final PcapHeader header = new PcapHeader(Type.POINTER);

	/**
	 * Copies contents of the buffer to new packet. All of the contents of the
	 * buffer are deep copied to new packet. The new packet allocates new memory
	 * for the packet contents, state and header if existing memory buffer is not
	 * large enough. Otherwise the existing memory buffer is overriden and reused.
	 * Existing buffers are not cleared before hand and may contain old data
	 * outside of the new header, state and packet data areas that are being
	 * overriden.
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 */
	public PcapPacket(byte[] buffer) {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * Copies contents of the buffer to new packet. All of the contents of the
	 * buffer are deep copied to new packet. The new packet allocates new memory
	 * for the packet contents, state and header if existing memory buffer is not
	 * large enough. Otherwise the existing memory buffer is overriden and reused.
	 * Existing buffers are not cleared before hand and may contain old data
	 * outside of the new header, state and packet data areas that are being
	 * overriden.
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 */
	public PcapPacket(ByteBuffer buffer) {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * Allocates a memory buffer large enough to hold atleast size bytes of data
	 * and the decoded packet state. The size of the the state structure is
	 * estimated to contain maximum of {@literal DEFAULT_STATE_HEADER_COUNT}
	 * headers.
	 * 
	 * @param size
	 *          amount of memory to allocate to hold packet data
	 */
	public PcapPacket(int size) {
		super(size, STATE_SIZE);
	}

	/**
	 * Allocates memory for packet data and certain amount of state and headers.
	 * 
	 * @param size
	 *          number of bytes for packet data
	 * @param headerCount
	 *          maximum number of header to allocate space for
	 */
	public PcapPacket(int size, int headerCount) {
		super(size, PcapHeader.sizeof() + JPacket.State.sizeof(headerCount));
	}

	/**
	 * Copies contents of the buffer to new packet. All of the contents of the
	 * buffer are deep copied to new packet. The new packet allocates new memory
	 * for the packet contents, state and header if existing memory buffer is not
	 * large enough. Otherwise the existing memory buffer is overriden and reused.
	 * Existing buffers are not cleared before hand and may contain old data
	 * outside of the new header, state and packet data areas that are being
	 * overriden.
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 */
	public PcapPacket(JBuffer buffer) {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * Does a deep copy of the source packet into newly allocated native memory
	 * location.
	 * 
	 * @param src
	 *          source packet
	 */
	public PcapPacket(JPacket src) {
		super(Type.POINTER);

		if (src instanceof PcapPacket) {
			((PcapPacket) src).transferStateAndDataTo(this);
		} else {
			throw new UnsupportedOperationException(
					"Unsupported packet type for this constructor");
		}
	}

	/**
	 * Allocates memory for new packet and copies both the header and packet
	 * buffer to newly allocated memory. Packet state is uninitialized and needs
	 * to be decoded.
	 * 
	 * @param header
	 *          capture header
	 * @param buffer
	 *          packet data buffer
	 */
	public PcapPacket(PcapHeader header, ByteBuffer buffer) {
		super(Type.POINTER);

		transferHeaderAndDataFrom0(header, buffer);
	}

	/**
	 * Allocates memory for new packet and copies both the header and packet
	 * buffer to newly allocated memory. Packet state is uninitialized and needs
	 * to be decoded.
	 * 
	 * @param header
	 *          capture header
	 * @param buffer
	 *          packet data buffer
	 */
	public PcapPacket(PcapHeader header, JBuffer buffer) {
		super(Type.POINTER);

		transferHeaderAndDataFrom0(header, buffer);
	}

	/**
	 * Does a deep copy of the source packet into newly allocated native memory
	 * location.
	 * 
	 * @param src
	 *          source packet
	 */
	public PcapPacket(PcapPacket src) {
		super(Type.POINTER);

		src.transferStateAndDataTo(this);
	}

	/**
	 * Special type of instantiation that allows an empty packet to be peered, or
	 * in C terms its a packet pointer with no actual memory allocated. Accessing
	 * most methods in this packet object before its initialized will throw
	 * NullPointerException as the object has not been initialized yet.
	 * 
	 * @param type
	 *          state of the object to create
	 */
	public PcapPacket(Type type) {
		super(type);
	}

	/**
	 * Retrieves the PcapHeader, capture header provided by libpcap.
	 * 
	 * @return capture header
	 */
	@Override
	public PcapHeader getCaptureHeader() {
		return header;
	}

	/**
	 * Gets the total size of the packet including pcap header, decoded state and
	 * data buffer.
	 * 
	 * @return total size of the packet in bytes
	 */
	@Override
	public int getTotalSize() {
		return super.size() + state.size() + header.size();
	}

	/**
	 * Peers both header and data to buffer. The buffer must contain first header
	 * then packet data layout in its memory. Packet state is uninitialized.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return number of bytes peered
	 */
	public int peerHeaderAndData(JBuffer buffer) {
		int o = header.peer(buffer, 0);
		o += super.peer(buffer, o, buffer.size() - header.size());

		return o;
	}

	/**
	 * Peer.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peer(PcapHeader header, JBuffer buffer) {
		int o = this.header.peerTo(header, 0);
		o += this.peer(buffer);

		return o;
	}

	/**
	 * Peer and scan.
	 * 
	 * @param dlt
	 *          the dlt
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peerAndScan(int dlt, PcapHeader header, JBuffer buffer) {
		int o = this.header.peerTo(header, 0);
		o += this.peer(buffer);

		scan(dlt);

		return o;
	}

	/**
	 * Peer header and data.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 * @throws PeeringException
	 *           the peering exception
	 */
	public int peerHeaderAndData(PcapHeader header, ByteBuffer buffer)
			throws PeeringException {
		int o = this.header.peerTo(header, 0);
		o += super.peer(buffer);

		return o;
	}

	/**
	 * Peer header and data.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peerHeaderAndData(PcapHeader header, JBuffer buffer) {
		int o = this.header.peerTo(header, 0);
		o += super.peer(buffer);

		return o;
	}

	/**
	 * Peers the contents of the buffer directly with this packet. No copies are
	 * performed but the capture header, packet state and data are expected to be
	 * contained within the buffer with a certain layout as described below:
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          Buffer containing packet header, state and data. Position property
	 *          specifies that start within the buffer where to peer the first
	 *          byte.
	 * @return number of bytes that were peered out of the buffer
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
	 * performed but the capture header, packet state and data are expected to be
	 * contained within the buffer with a certain layout as described below:
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing packet header, state and data
	 * @return number of bytes that were peered out of the buffer
	 */
	public int peerStateAndData(JBuffer buffer) {
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * Peer state and data.
	 * 
	 * @param memory
	 *          the memory
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	private int peerStateAndData(JBuffer memory, int offset) {

		int o = header.peer(memory, offset);
		state.peerTo(memory, offset + o, State.sizeof(0));
		o += state.peerTo(memory, offset + o, State.sizeof(state.getHeaderCount()));
		o += super.peer(memory, offset + o, header.caplen());

		return o;
	}

	/**
	 * Copies contents of header and packet buffer to a single newly allocated
	 * buffer. State is uninitialized. The packet's header and buffer's are peered
	 * with newly allocated buffer.
	 * 
	 * @param header
	 *          source header
	 * @param buffer
	 *          source packet data buffer
	 * @return number of bytes copied.
	 */
	public int transferHeaderAndDataFrom(PcapHeader header, ByteBuffer buffer) {
		return transferHeaderAndDataFrom0(header, buffer);
	}

	/**
	 * Transfer header and data from0.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	private int transferHeaderAndDataFrom0(PcapHeader header, ByteBuffer buffer) {
		return getMemoryPool().duplicate2(header, buffer, this.header, this);
	}

	/**
	 * Copies contents of header and packet buffer to a single newly allocated
	 * buffer. State is uninitialized. The packet's header and buffer's are peered
	 * with newly allocated buffer.
	 * 
	 * @param header
	 *          source header
	 * @param buffer
	 *          source packet data buffer
	 * @return number of bytes copied.
	 */
	public int transferHeaderAndDataFrom(PcapHeader header, JBuffer buffer) {
		return transferHeaderAndDataFrom0(header, buffer);
	}

	/**
	 * Transfer header and data from0.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	private int transferHeaderAndDataFrom0(PcapHeader header, JBuffer buffer) {
		return getMemoryPool().duplicate2(header, buffer, this.header, this);
	}

	/**
	 * Copies contents of the buffer to new packet. All of the contents of the
	 * buffer are deep copied to new packet. The new packet allocates new memory
	 * for the packet contents, state and header if existing memory buffer is not
	 * large enough. Otherwise the existing memory buffer is overriden and reused.
	 * Existing buffers are not cleared before hand and may contain old data
	 * outside of the new header, state and packet data areas that are being
	 * overriden.
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(byte[] buffer) {

		JBuffer b = getMemoryBuffer(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * Copies contents of the buffer to new packet. All of the contents of the
	 * buffer are deep copied to new packet. The new packet allocates new memory
	 * for the packet contents, state and header if existing memory buffer is not
	 * large enough. Otherwise the existing memory buffer is overriden and reused.
	 * Existing buffers are not cleared before hand and may contain old data
	 * outside of the new header, state and packet data areas that are being
	 * overriden.
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          Buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer. Current buffer position points at the
	 *          start of pcap header.
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(ByteBuffer buffer) {
		final int len = buffer.limit() - buffer.position();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer, 0);

		return peerStateAndData(b, 0);
	}

	/**
	 * Copies contents of the buffer to new packet. All of the contents of the
	 * buffer are deep copied to new packet. The new packet allocates new memory
	 * for the packet contents, state and header if existing memory buffer is not
	 * large enough. Otherwise the existing memory buffer is overriden and reused.
	 * Existing buffers are not cleared before hand and may contain old data
	 * outside of the new header, state and packet data areas that are being
	 * overriden.
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(JBuffer buffer) {
		final int len = buffer.size();
		JBuffer b = getMemoryBuffer(len);

		buffer.transferTo(b);

		return peerStateAndData(b, 0);
	}

	/**
	 * Deep copy of the supplied packet to this packet. Contents of the supplied
	 * packet such as pcap header, packet state and packet data are deep copied
	 * into newly allocated memory if necessary or existing memory buffer if it is
	 * large enough to hold the new packet with its complete state. In either
	 * case, the new packet will be stored with its header and state in a single
	 * contigues buffer.
	 * 
	 * @param packet
	 *          source packet from which to copy from
	 * @return number of bytes copied
	 */
	public int transferStateAndDataFrom(PcapPacket packet) {
		return packet.transferStateAndDataTo(this);
	}

	/**
	 * Copies contents of this packet to buffer. The packets capture header, state
	 * and packet data are copied to new buffer. After completion of this
	 * operation the complete contents and state of the packet will be transfered
	 * to the buffer. The layout of the buffer data will be as described below. A
	 * buffer with this type of layout is suitable for any transferStateAndData or
	 * peer methods for any buffers that are JMemory based. The buffer has to be
	 * large enough to hold all of the packet content as returned by method
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 * @return number of bytes copied {@link #getTotalSize()}. If the buffer is
	 *         too small and a runtime exception may be thrown.
	 *         <p>
	 *         The buffer layout will look like the following:
	 * 
	 *         <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 *         </p>
	 */
	public int transferStateAndDataTo(byte[] buffer) {
		int o = header.transferTo(buffer, 0);
		o += state.transferTo(buffer, o);
		o += super.transferTo(buffer, 0, size(), o);

		return o;
	}

	/**
	 * Copies contents of this packet to buffer. The packets capture header, state
	 * and packet data are copied to new buffer. After completion of this
	 * operation the complete contents and state of the packet will be transfered
	 * to the buffer. The layout of the buffer data will be as described below. A
	 * buffer with this type of layout is suitable for any transferStateAndData or
	 * peer methods for any buffers that are JMemory based. The buffer has to be
	 * large enough to hold all of the packet content as returned by method
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 * @return number of bytes copied {@link #getTotalSize()}. If the buffer is
	 *         too small and a runtime exception may be thrown.
	 *         <p>
	 *         The buffer layout will look like the following:
	 * 
	 *         <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 *         </p>
	 */
	public int transferStateAndDataTo(ByteBuffer buffer) {
		int o = header.transferTo(buffer);
		o += state.transferTo(buffer);
		o += super.transferTo(buffer);

		return o;
	}

	/**
	 * Copies contents of this packet to buffer. The packets capture header, state
	 * and packet data are copied to new buffer. After completion of this
	 * operation the complete contents and state of the packet will be transfered
	 * to the buffer. The layout of the buffer data will be as described below. A
	 * buffer with this type of layout is suitable for any transferStateAndData or
	 * peer methods for any buffers that are JMemory based. The buffer has to be
	 * large enough to hold all of the packet content as returned by method
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 * @return number of bytes copied {@link #getTotalSize()}. If the buffer is
	 *         too small and a runtime exception may be thrown.
	 *         <p>
	 *         The buffer layout will look like the following:
	 * 
	 *         <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 *         </p>
	 */
	public int transferStateAndDataTo(JBuffer buffer) {
		return transferStateAndDataTo(buffer, 0);
	}

	/**
	 * Copies contents of this packet to buffer. The packets capture header, state
	 * and packet data are copied to new buffer. After completion of this
	 * operation the complete contents and state of the packet will be transfered
	 * to the buffer. The layout of the buffer data will be as described below. A
	 * buffer with this type of layout is suitable for any transferStateAndData or
	 * peer methods for any buffers that are JMemory based. The buffer has to be
	 * large enough to hold all of the packet content as returned by method
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 * @param offset
	 *          the offset
	 * @return number of bytes copied {@link #getTotalSize()}. If the buffer is
	 *         too small and a runtime exception may be thrown.
	 *         <p>
	 *         The buffer layout will look like the following:
	 * 
	 *         <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 *         </p>
	 */
	public int transferStateAndDataTo(JBuffer buffer, int offset) {
		int o = header.transferTo(buffer, offset);
		o += state.transferTo(buffer, 0, state.size(), offset + o);
		o += super.transferTo(buffer, 0, size(), offset + o);

		return o;
	}

	/**
	 * Deep copy of the this packet to the supplied packet. Contents of the this
	 * packet such as pcap header, packet state and packet data are deep copied
	 * into the suppliedpacket, allocating memory if necessary or existing memory
	 * buffer if it is large enough to hold the new packet with its complete
	 * state. In either case, the packet will be stored with its header and state
	 * in a single contigues buffer in the supplied packet.
	 * 
	 * @param packet
	 *          destination packet to which to copy header, state and packet data
	 * @return number of bytes copied
	 */
	public int transferStateAndDataTo(PcapPacket packet) {
		JBuffer buffer = packet.getMemoryBuffer(this.getTotalSize());

		int o = header.transferTo(buffer, 0);
		packet.header.peerTo(buffer, 0);

		packet.state.peerTo(buffer, o, state.size());
		o += state.transferTo(packet.state);

		packet.peer(buffer, o, size());
		o += this.transferTo(buffer, 0, size(), o);

		return o;
	}
}
