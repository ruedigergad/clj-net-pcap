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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.AnnotatedJField;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * A base class for all protocol header definitions.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JHeader extends JBuffer implements JPayloadAccessor {

	/**
	 * This class is peered state of a header a native state structure
	 * 
	 * <pre>
	 * typedef struct header_t {
	 *   uint8_t  hdr_id;         // header ID
	 * 
	 *   uint8_t  hdr_prefix;     // length of the prefix (preamble) before the header
	 *   uint8_t  hdr_gap;        // length of the gap between header and payload
	 *   uint16_t hdr_flags;      // flags for this header
	 *   uint16_t hdr_postfix;    // length of the postfix (trailer) after the payload
	 *   uint32_t hdr_offset;     // offset into the packet_t-&gt;data buffer
	 *   uint32_t hdr_length;     // length of the header in packet_t-&gt;data buffer
	 *   uint32_t hdr_payload;    // length of the payload
	 * 
	 *   jobject  hdr_analysis;   // Java JAnalysis based object if not null
	 * } header_t;
	 * 
	 * </pre>
	 * 
	 * .
	 * 
	 * @author Sly Technologies, Inc.
	 */
	public static class State extends JStruct {

		/**
		 * Flag set in the header_t structure, tells if the CRC, if performed, was
		 * valid or invalid. Invalid CRC means that computed CRC did not match the
		 * protocol specific CRC stored within the header.
		 */
		public final static int FLAG_CRC_INVALID = 0x0080;

		/**
		 * Flag set in the header_t structure, a protocol specific CRC had been
		 * performed on the frame, header or its payload.
		 */
		public final static int FLAG_CRC_PERFORMED = 0x0040;

		/**
		 * Flag set in the header_t structure, which tells if the postifx is
		 * incomplete due to packet truncation at the time of the capture.
		 */
		public final static int FLAG_GAP_TRUNCATED = 0x0008;

		/**
		 * Flag set in the header_t structure, which tells if the header is
		 * incomplete due to packet truncation at the time of the capture.
		 */
		public final static int FLAG_HEADER_TRUNCATED = 0x0002;

		/**
		 * Flag set in the header_t structure, which tells if this header was bound
		 * due to a heuristic binding. If set, this means that the header was found
		 * heuristically (guessed based on correctness of the field values within
		 * the header). It is always possible, that heuristic binding may be
		 * incorrect and this flag, provides a way to determine how trust worthy the
		 * binding is.
		 */
		public final static int FLAG_HEURISTIC_BINDING = 0x0020;

		/**
		 * Flag set in the header_t structure, which tells if the payload is
		 * incomplete due to packet truncation at the time of the capture. Only
		 * protocols with a payload buffer of static length would set this flag or
		 * if the payload buffer is at the end of the packet and a calculation can
		 * determine based on over-all packet trancation, if the payload was
		 * affected as well.
		 */
		public final static int FLAG_PAYLOAD_TRUNCATED = 0x0004;

		/**
		 * Flag set in the header_t structure, which tells if the postifx is
		 * incomplete due to packet truncation at the time of the capture.
		 */
		public final static int FLAG_POSTFIX_TRUNCATED = 0x0010;

		/**
		 * Flag set in the header_t structure, which tells if the prefix is
		 * incomplete due to packet truncation at the time of the capture.
		 */
		public final static int FLAG_PREFIX_TRUNCATED = 0x0001;

		/**
		 * Flag set in the header_t structure, which indicates that the current
		 * header and/or payload are fragmented. The header fragmentation could have
		 * been determined by the scanner of this protocol or the flag could have
		 * been inherited from encapsulating header.
		 */
		public final static int FLAG_HEADER_FRAGMENTED = 0x0100;

		/**
		 * Flag set in the header_t structure, which indicates that the current
		 * header was dissected for optional fields. All optional fields were
		 * recorded.
		 */
		public final static int FLAG_FIELDS_DISSECTED = 0x0200;

		/**
		 * Flag set in the header_t structure, which indicates that the current
		 * header was dissected for optional sub-headers. All optional sub-headers
		 * were recorded.
		 */
		public final static int FLAG_SUBHEADERS_DISSECTED = 0x0400;

		/**
		 * A flag that is set for headers that should not strictly enforce their
		 * header boundaries. This is used in cases such as encapsulated IP and ICMP
		 * header, where the original IP packet was truncated before encapsulating
		 * in ICMP, yet its header tot_length was not adjusted.
		 */
		public final static int FLAG_IGNORE_BOUNDS = 0x0800;

		/** Name of the native structure backing this peer class. */
		public final static String STRUCT_NAME = "header_t";

		/**
		 * Create an uninitialized type.
		 * 
		 * @param type
		 *          type of memory
		 */
		public State(Type type) {
			super(STRUCT_NAME, type);
		}

		/**
		 * Every header "record" keeps int-bit-flags that describe certain
		 * additional information about the header. Most commonly use flags are
		 * 
		 * @return unsigned integer contains bit-flags for this header
		 *         {@link #FLAG_PAYLOAD_TRUNCATED} and other like it.
		 */
		public native int getFlags();

		/**
		 * Gets the length in bytes of a gap (padding) between the header and the
		 * protocol 'records' payload:
		 * 
		 * <pre>
		 * +------------------=====--------------------+
		 * | prefix | header | GAP | payload | postfix |
		 * +------------------=====--------------------+
		 * </pre>
		 * 
		 * .
		 * 
		 * @return length in bytes of the gap or 0 if not set
		 */
		public native int getGap();

		/**
		 * Gets the numerical ID of the header this structure describes as defined
		 * by <code>JRegistry</code>.
		 * 
		 * @return numerical ID of this header
		 * @see JRegistry
		 */
		public native int getId();

		/**
		 * Gets the length of the protocol's header in bytes within the protocol's
		 * 'record':
		 * 
		 * <pre>
		 * +---------========--------------------------+
		 * | prefix | HEADER | gap | payload | postfix |
		 * +---------========--------------------------+
		 * </pre>
		 * 
		 * .
		 * 
		 * @return length in bytes of the header
		 */
		public native int getLength();

		/**
		 * Gets the offset into the packet buffer of the actual protocol header
		 * header in bytes of protocols 'record':
		 * 
		 * <pre>
		 * +---------========--------------------------+
		 * | prefix | HEADER | gap | payload | postfix |
		 * +---------========--------------------------+
		 * </pre>
		 * 
		 * .
		 * 
		 * @return offset in bytes of the header
		 */
		public native int getOffset();

		/**
		 * Gets the length of the payload that follows a protocol header in bytes
		 * within the protocol's 'record':
		 * 
		 * <pre>
		 * +------------------------=========----------+
		 * | prefix | header | gap | PAYLOAD | postfix |
		 * +------------------------=========----------+
		 * </pre>
		 * 
		 * .
		 * 
		 * @return length in bytes of the payload or 0 if not set
		 */
		public native int getPayload();

		/**
		 * Gets the length of the postfix that follows a protocol's payload in bytes
		 * within the protocol's 'record':
		 * 
		 * <pre>
		 * +----------------------------------=========+
		 * | prefix | header | gap | payload | POSTFIX |
		 * +----------------------------------=========+
		 * </pre>
		 * 
		 * .
		 * 
		 * @return length in bytes of the postfix or 0 if not set
		 */
		public native int getPostfix();

		/**
		 * Gets the length of the prefix that precedes a protocol's header in bytes
		 * within the protocol's 'record':
		 * 
		 * <pre>
		 * +========-----------------------------------+
		 * | PREFIX | header | gap | payload | postfix |
		 * +========-----------------------------------+
		 * </pre>
		 * 
		 * .
		 * 
		 * @return length in bytes of the postfix or 0 if not set
		 */
		public native int getPrefix();

		/**
		 * Checks if this state object is reading for native structures or has a
		 * java implementation backing it.
		 * 
		 * @return true if the implementation is native, otherwise false
		 */
		public boolean isDirect() {
			return true;
		}

		/**
		 * Peers this state object with the native structures of another. No copies
		 * are done, only references are changed.
		 * 
		 * @param peer
		 *          destination object holding the native memory reference we need
		 *          to peer to
		 * @return number of bytes that actually were part of the operation even
		 *         though non were physically copied during the peering process
		 */
		public int peer(State peer) {
			if (peer.isDirect() == false) {
				throw new IllegalStateException(
						"DirectState can only peer with another DirectState");
			}
			return super.peer(peer);
		}

		/**
		 * Sets the header flags to new values.
		 * 
		 * @param flags
		 *          unsinged integer containing the bit-flags to set for this header
		 */
		public native void setFlags(int flags);

		/**
		 * Creates a string containing light debug information about this state
		 * class and underlying header it belongs to.
		 * 
		 * @return light debug string for this object and header
		 */
		@Override
		public String toString() {
			return "(id=" + getId() + ", offset=" + getOffset() + ", length="
					+ getLength() + ")";
		}
	}

	/**
	 * A constant that defines how many bits there are in a byte. This constant is
	 * used in unit conversion from bytes to bits and visa-versa. To convert from
	 * bytes to bit you multiple your number of bytes by the BYTE constant. To
	 * convert from bits to bytes, you divide the number of bits by the BYTE
	 * constant.
	 */
	public final static int BYTE = 8;

	/** No fields. */
	private final static JField[] DEFAULT_FIELDS = new JField[0];

	/** The Constant EMPTY_HEADER_ARRAY. */
	protected final static JHeader[] EMPTY_HEADER_ARRAY = new JHeader[0];

	/**
	 * Gets the size of the native header_t structure on this particular platform.
	 * 
	 * @return length in bytes
	 */
	public native static int sizeof();

	/** The annotated header. */
	protected AnnotatedHeader annotatedHeader;

	/** The fields. */
	private JField[] fields;

	/** The id. */
	private int id;

	/** The is sub header. */
	protected boolean isSubHeader = false;

	/** The name. */
	private String name;

	/** The nicname. */
	private String nicname;

	/** A reference to the packet that this header is part of. */
	protected JPacket packet;

	/** Reference to header's native state structure. */
	protected final State state;

	/** The index. */
	private int index = -1;

	/**
	 * Calls on the header defintion's static annotated \@HeaderLength method to
	 * get header's length. The method is given a buffer and offset as the start
	 * of the header. The method invoked must be defined in the header definition
	 * otherwise an exception will be thrown.
	 */
	public JHeader() {
		super(Type.POINTER);
		order(ByteOrder.BIG_ENDIAN); // network byte order by default
		state = new State(Type.POINTER);

		final JProtocol protocol = JProtocol.valueOf(getClass());

		AnnotatedHeader header;
		if (protocol != null) {
			this.id = protocol.getId();
			header = JRegistry.lookupAnnotatedHeader(protocol);

		} else {
			this.id = JRegistry.lookupId(getClass());
			header = JRegistry.lookupAnnotatedHeader(getClass());
		}

		initFromAnnotatedHeader(header);
	}

	/**
	 * Constructs a header and initializes its static fields.
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 */
	public JHeader(int id, JField[] fields, String name) {
		this(id, fields, name, name);
	}

	/**
	 * Constructs a header and initializes its static fields.
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(int id, JField[] fields, String name, String nicname) {
		super(Type.POINTER);
		this.fields = fields;

		this.id = id;
		this.name = name;
		this.nicname = nicname;
		this.state = new State(Type.POINTER);
		super.order(ByteOrder.nativeOrder());

	}

	/**
	 * Constructs a header.
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param name
	 *          comprehensive name of the protocol
	 */
	public JHeader(int id, String name) {
		this(id, name, name);
	}

	/**
	 * Constructs a header.
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(int id, String name, String nicname) {
		this(id, DEFAULT_FIELDS, name, nicname);
	}

	/**
	 * Constructs a header for a CORE protocol.
	 * 
	 * @param protocol
	 *          the CORE protocol constant
	 */
	public JHeader(JProtocol protocol) {
		super(Type.POINTER);
		order(ByteOrder.BIG_ENDIAN); // network byte order by default
		state = new State(Type.POINTER);

		this.id = protocol.getId();
		AnnotatedHeader header = JRegistry.lookupAnnotatedHeader(protocol);

		initFromAnnotatedHeader(header);
	}

	/**
	 * Constructs a header and initializes its static fields.
	 * 
	 * @param state
	 *          the default header state object being referenced
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(State state, JField[] fields, String name, String nicname) {
		super(Type.POINTER);

		this.state = state;
		this.fields = fields;
		this.name = name;
		this.nicname = nicname;
		this.id = state.getId();
		super.order(ByteOrder.nativeOrder());
	}

	/**
	 * Method that gets called everytime a header is successfully peered with new
	 * buffer and/or state structure. This method in JHeader is empty and is
	 * expected to be overriden by subclasses of JHeader that require special
	 * processing of the header such as decoding its structure at runtime when the
	 * header object is bound to new state.
	 */
	public final void decode() {
		decodeHeader();
		validateHeader();
	}

	/**
	 * Allows a header to decode its complex fields.
	 */
	protected void decodeHeader() {
		// Empty
	}

	/**
	 * Retrieves the cached annotation of the header definition file. The
	 * AT-Header annotation is a class that contains all of the annotation
	 * parameters that were set in the definition file or its defaults.
	 * 
	 * @return annotation class for the source header definition
	 */
	public AnnotatedHeader getAnnotatedHeader() {
		return this.annotatedHeader;
	}

	/**
	 * Retrives the description property for this header as defined in the source
	 * definition.
	 * 
	 * @return a short description of this protocol and the header
	 */
	public String getDescription() {
		return annotatedHeader.getDescription();
	}

	/**
	 * Retrieves the fields at runtime, that this header has so that they may be
	 * used by a formatter.
	 * 
	 * @return an array of fields that this header is made up of, as determined at
	 *         runtime
	 */
	public JField[] getFields() {

		JField.sortFieldByOffset(fields, this, true);

		return this.fields;
	}

	/**
	 * Reads the contents of the protocol's 'record' gap property as a byte array.
	 * 
	 * <pre>
	 * +------------------=====--------------------+
	 * | prefix | header | GAP | payload | postfix |
	 * +------------------=====--------------------+
	 * </pre>
	 * 
	 * @return contents of the gap or zero length byte[] if not set
	 */
	public byte[] getGap() {
		return packet.getByteArray(getGapOffset(), getGapLength());
	}

	/**
	 * Reads the length of the gap between the header and payload: *
	 * 
	 * <pre>
	 * +------------------=====--------------------+
	 * | prefix | header | GAP | payload | postfix |
	 * +------------------=====--------------------+
	 * </pre>
	 * 
	 * .
	 * 
	 * @return length of the gap in bytes or 0 if not set
	 */
	public int getGapLength() {
		return state.getGap();
	}

	/**
	 * Gets the offset into the packet, not the header, where the gap starts. Even
	 * if the gap is zero length or not set, the offset is still calculated and
	 * will always be the first byte past the header.
	 * 
	 * <pre>
	 * +------------------=====--------------------+
	 * | prefix | header | GAP | payload | postfix |
	 * +------------------=====--------------------+
	 * </pre>
	 * 
	 * @return offset in bytes into the packet's buffer
	 */
	public int getGapOffset() {
		return getOffset() + getHeaderLength();
	}

	/**
	 * Convenience method that retrieves the contents of the header as a byte are
	 * 
	 * <pre>
	 * +---------========--------------------------+
	 * | prefix | HEADER | gap | payload | postfix |
	 * +---------========--------------------------+
	 * </pre>
	 * 
	 * .
	 * 
	 * @return the contents of the header
	 */
	public byte[] getHeader() {
		return packet.getByteArray(getHeaderOffset(), getHeaderLength());
	}

	/**
	 * Length of the header in bytes. *
	 * 
	 * <pre>
	 * +---------========--------------------------+
	 * | prefix | HEADER | gap | payload | postfix |
	 * +---------========--------------------------+
	 * </pre>
	 * 
	 * @return the length in bytes fo the header
	 */
	public int getHeaderLength() {
		return state.getLength();
	}

	/**
	 * Gets the offset in bytes into the packet, of the start of the header. *
	 * 
	 * <pre>
	 * +---------========--------------------------+
	 * | prefix | HEADER | gap | payload | postfix |
	 * +---------========--------------------------+
	 * </pre>
	 * 
	 * @return offset in bytes into the packet buffer
	 */
	public int getHeaderOffset() {
		return state.getOffset();
	}

	/**
	 * Gets the numerical ID of this protocol header at runtime as assigned by the
	 * JRegistry.
	 * 
	 * @return unique numerical ID of this header
	 */
	public final int getId() {
		return this.id;
	}

	/**
	 * Length of this header within the buffer.
	 * 
	 * @return length in bytes
	 */
	public int getLength() {
		return this.state.getLength();
	}

	/**
	 * Gets the comprehensive name for this header.
	 * 
	 * @return the name full name of this header
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * Gets the short name for this header.
	 * 
	 * @return the nicname for this header
	 */
	public final String getNicname() {
		return this.nicname;
	}

	/**
	 * Offset into the packet buffer.
	 * 
	 * @return offset into the buffer in bytes
	 */
	public int getOffset() {
		return state.getOffset();
	}

	/**
	 * Gets the packet that this header is associated with
	 * 
	 * @return parent packet
	 */
	public final JPacket getPacket() {
		return this.packet;
	}

	/**
	 * If this is a sub-header of another header, gets the reference to the parent
	 * header.
	 * 
	 * @return the parent header if sub-header, otherwise returns a reference to
	 *         itself
	 */
	public JHeader getParent() {
		return this;
	}

	/**
	 * Retrieves the playload data portion of the packet right after the current
	 * header.
	 * 
	 * <pre>
	 * +------------------------=========----------+
	 * | prefix | header | gap | PAYLOAD | postfix |
	 * +------------------------=========----------+
	 * </pre>
	 * 
	 * @return newly allocated byte array containing copy of the contents of the
	 *         header's payload from the packet.
	 */
	public byte[] getPayload() {
		return packet.getByteArray(getPayloadOffset(), getPayloadLength());
	}

	/**
	 * Gets the length in bytes of the payload that follows the header and the
	 * gap. The length reflects the actual data that resides in the captured
	 * packet, not neccessarily all of the data that was originaly transmited if
	 * the packet has been trucated during capture.
	 * 
	 * <pre>
	 * +------------------------=========----------+
	 * | prefix | header | gap | PAYLOAD | postfix |
	 * +------------------------=========----------+
	 * </pre>
	 * 
	 * @return length of the payload in bytes
	 */
	public int getPayloadLength() {
		return state.getPayload();
	}

	/**
	 * Gets the offset of the payload into the packet buffer.
	 * 
	 * <pre>
	 * +------------------------=========----------+
	 * | prefix | header | gap | PAYLOAD | postfix |
	 * +------------------------=========----------+
	 * </pre>
	 * 
	 * @return the start of the payload within the packet buffer
	 */
	public int getPayloadOffset() {
		return getGapOffset() + getGapLength();
	}

	/**
	 * Gets the contents of the postfix as a byte array.
	 * 
	 * @return the contents of the postfix as a byte array or zero length byte
	 *         array if no postfix set
	 */
	public byte[] getPostfix() {
		return packet.getByteArray(getPostfixOffset(), getPostfixLength());
	}

	/**
	 * Gets the length of the postfix.
	 * 
	 * <pre>
	 * +----------------------------------=========+
	 * | prefix | header | gap | payload | POSTFIX |
	 * +----------------------------------=========+
	 * </pre>
	 * 
	 * @return the length of the postfix in bytes or zero if not set
	 */
	public int getPostfixLength() {
		return state.getPostfix();
	}

	/**
	 * Gets the offset in bytes into the packet buffer of the start of the
	 * postfix, even if not set or zero length.
	 * 
	 * @return the offeset into the packet buffer in bytes
	 */
	public int getPostfixOffset() {
		return getPayloadOffset() + getPayloadLength();
	}

	/**
	 * Gets the contents of the prefix in a byte array.
	 * 
	 * <pre>
	 * +========-----------------------------------+
	 * | PREFIX | header | gap | payload | postfix |
	 * +========-----------------------------------+
	 * </pre>
	 * 
	 * @return the contents of the prefix or zero length byte array if not set
	 */
	public byte[] getPrefix() {
		return packet.getByteArray(getPrefixOffset(), getPrefixLength());
	}

	/**
	 * The length in bytes of the prefix within the packet buffer. Zero if not
	 * set.
	 * 
	 * @return the length in bytes within the packet buffer
	 */
	public int getPrefixLength() {
		return state.getPrefix();
	}

	/**
	 * The offset in bytes into the packet buffer where the prefix starts, even if
	 * prefix is not set or zero in length.
	 * 
	 * @return offset in bytes into the packet buffer
	 */
	public int getPrefixOffset() {
		return getOffset() - getPrefixLength();
	}

	/**
	 * Gets the reference to the current header's native state structure
	 * 
	 * @return current state of the header
	 */
	public State getState() {
		return state;
	}

	/**
	 * Gets an array of currently defined sub headers.
	 * 
	 * @return array of sub headers
	 */
	public JHeader[] getSubHeaders() {
		return EMPTY_HEADER_ARRAY;
	}

	/**
	 * Checks if description header property has been set that provides a short
	 * description of this header.
	 * 
	 * @return true if header description has been set in Header annotation
	 */
	public boolean hasDescription() {
		return annotatedHeader.getDescription() != null;
	}

	/**
	 * Checks if gap has been set.
	 * 
	 * @return true if set, otherwise false
	 */
	public boolean hasGap() {
		return getGapLength() != 0;
	}

	/**
	 * Checks if payload has been set.
	 * 
	 * @return true if set, otherwise false
	 */
	public boolean hasPayload() {
		return getPayloadLength() != 0;
	}

	/**
	 * Checks if postfix has been set.
	 * 
	 * @return true if set, otherwise false
	 */
	public boolean hasPostfix() {
		return getPostfixLength() != 0;
	}

	/**
	 * Checks if prefix has been set.
	 * 
	 * @return true if set, otherwise false
	 */
	public boolean hasPrefix() {
		return getPrefixLength() != 0;
	}

	/**
	 * Checks if header has any sub-headers.
	 * 
	 * @return true if set, otherwise false
	 */
	public boolean hasSubHeaders() {
		return false;
	}

	/**
	 * Initialize this header directly from annotated header definition class.
	 * 
	 * @param header
	 *          annotation to initialize from
	 */
	private void initFromAnnotatedHeader(AnnotatedHeader header) {
		this.annotatedHeader = header;

		this.name = header.getName();
		this.nicname = header.getNicname();

		this.fields = AnnotatedJField.fromAnnotatedFields(header.getFields());
	}

	/**
	 * Checks if gap has been truncated due to truncation at the time of the
	 * capture. If the gap was never set (initially set to zero) and then
	 * completely removed because of packet truncation, this method will return
	 * false, since the gap never existed in the first place.
	 * 
	 * @return true if truncated, otherwise false
	 */
	public boolean isGapTruncated() {
		return (state.getFlags() & State.FLAG_GAP_TRUNCATED) != 0;
	}

	/**
	 * Checks if header has been truncated due to truncation at the time of the
	 * capture.
	 * 
	 * @return true if truncated, otherwise false
	 */
	public boolean isHeaderTruncated() {
		return (state.getFlags() & State.FLAG_HEADER_TRUNCATED) != 0;
	}

	/**
	 * Checks if payload has been truncated due to truncation at the time of the
	 * capture. If the payload was never set (initially set to zero) and then
	 * completely removed because of packet truncation, this method will return
	 * false, since the payload never existed in the first place.
	 * 
	 * @return true if truncated, otherwise false
	 */
	public boolean isPayloadTruncated() {
		return (state.getFlags() & State.FLAG_PAYLOAD_TRUNCATED) != 0;
	}

	/**
	 * Checks if postifx has been truncated due to truncation at the time of the
	 * capture. If the postifx was never set (initially set to zero) and then
	 * completely removed because of packet truncation, this method will return
	 * false, since the postfix never existed in the first place.
	 * 
	 * @return true if truncated, otherwise false
	 */
	public boolean isPostfixTruncated() {
		return (state.getFlags() & State.FLAG_POSTFIX_TRUNCATED) != 0;
	}

	/**
	 * Checks if prefix has been truncated due to truncation at the time of the
	 * capture. If the prefix was never set (initially set to zero) and then
	 * completely removed because of packet truncation, this method will return
	 * false, since the gap never existed in the first place.
	 * 
	 * @return true if truncated, otherwise false
	 */
	public boolean isPrefixTruncated() {
		return (state.getFlags() & State.FLAG_PREFIX_TRUNCATED) != 0;
	}

	/**
	 * Peers this state object with the buffer at specified offset.
	 * 
	 * @param buffer
	 *          buffer to peer to
	 * @param offset
	 *          offset into the buffer
	 * @return number of bytes that were peered, not copied
	 */
	public int peer(JBuffer buffer, int offset) {
		// int length = this.lengthMethod.getHeaderLength(buffer, offset);
		//
		// return peer(buffer, offset, length);

		return 0;
	}

	/**
	 * Peers, associates a native packet buffer and scanner structure with this
	 * header. This header is unchanged while the header being passed in is
	 * rereferenced to point at this headers buffer and state structure.
	 * 
	 * @param header
	 *          the header to peer with this header
	 * @return number of bytes total that were peered with the supplied header
	 */
	public int peer(JHeader header) {
		this.state.peer(header.state);

		return super.peer(header, header.getOffset(), header.getLength());
	}

	/**
	 * Peers, without copy, the user supplied buffer with payload data portion of
	 * the packet right after the current header.
	 * 
	 * @param buffer
	 *          buffer to peer the data with
	 * @return the same buffer that was passed in
	 */
	public JBuffer peerPayloadTo(JBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		buffer.peer(packet, offset, packet.remaining(offset));

		return buffer;
	}

	/**
	 * Sets the packet that this header should be associated with
	 * 
	 * @param packet
	 *          packet to associate with this header
	 */
	public final void setPacket(JPacket packet) {
		this.packet = packet;
	}

	/**
	 * Allows sub-headers to be set.
	 * 
	 * @param headers
	 *          array of sub header
	 */
	public void setSubHeaders(JHeader[] headers) {
	}

	/**
	 * Gets a string with summary information about the header.
	 * 
	 * @return String with summary of the header
	 */
	@Override
	public String toString() {
		JFormatter out = JPacket.getFormatter();
		out.reset();
		try {
			out.format(this);
		} catch (IOException e) {
			throw new IllegalStateException("Unexpected StringBuilder IO error");
		}
		return out.toString();
	}

	/**
	 * Copies the payload data portion of the packet right after the current
	 * header to user supplied buffer.
	 * 
	 * @param buffer
	 *          buffer where the data will be written to
	 * @return the same buffer that was passed in
	 */
	public byte[] transferPayloadTo(byte[] buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		return packet.getByteArray(offset, buffer);
	}

	/**
	 * Copies into the user supplied buffer, the payload data portion of the
	 * packet right after the current header. The copy will start at the current
	 * ByteBuffer position property.
	 * 
	 * @param buffer
	 *          buffer to copy the data to
	 * @return the same buffer that was passed in
	 */
	public ByteBuffer transferPayloadTo(ByteBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		packet.transferTo(buffer, offset, packet.remaining(offset));

		return buffer;
	}

	/**
	 * Copies into the user supplied buffer, the payload data portion of the
	 * packet right after the current header.
	 * 
	 * @param buffer
	 *          buffer to copy the data to
	 * @return the same buffer that was passed in
	 */
	public JBuffer transferPayloadTo(JBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		packet.transferTo(buffer, offset, packet.remaining(offset), 0);

		return buffer;
	}

	/**
	 * Sets the index.
	 * 
	 * @param index
	 *          the new index
	 */
	void setIndex(int index) {
		this.index = index;
	}

	/**
	 * Gets the header's index into the packet state structure. Various pieces of
	 * information in packet state structure can be looked up using this index.
	 * 
	 * @return header index in Packet.State structure
	 */
	public int getIndex() {
		return this.index;
	}

	/**
	 * Allows a header to validate its values.
	 */
	protected void validateHeader() {

	}

	/**
	 * Checks for next header.
	 * 
	 * @return true, if successful
	 */
	public boolean hasNextHeader() {
		return this.index + 1 < packet.getState().getHeaderCount();
	}

	/**
	 * Gets the next header id.
	 * 
	 * @return the next header id
	 */
	public int getNextHeaderId() {
		return packet.getState().getHeaderIdByIndex(index + 1);
	}

	/**
	 * Gets the next header offset.
	 * 
	 * @return the next header offset
	 */
	public int getNextHeaderOffset() {
		return packet.getState().getHeaderOffsetByIndex(index + 1);
	}

	/**
	 * Checks for previous header.
	 * 
	 * @return true, if successful
	 */
	public boolean hasPreviousHeader() {
		return this.index > 0;
	}

	/**
	 * Gets the previous header id.
	 * 
	 * @return the previous header id
	 */
	public int getPreviousHeaderId() {
		return packet.getState().getHeaderIdByIndex(index - 1);
	}

	/**
	 * Gets the previous header offset.
	 * 
	 * @return the previous header offset
	 */
	public int getPreviousHeaderOffset() {
		return packet.getState().getHeaderOffsetByIndex(index - 1);
	}

	/**
	 * Checks if this entire header "record" which includes prefix, header, gap,
	 * payload and post is fragmented. The fragmentation may have happened in
	 * encapsulating protocol such as Ip. This property may be inherited from
	 * encapsulating headers.
	 * 
	 * @return true if this header is believed to be a fragment, otherwise false
	 */
	public boolean isFragmented() {
		return ((getState().getFlags() & JHeader.State.FLAG_HEADER_FRAGMENTED) > 0);
	}

}
