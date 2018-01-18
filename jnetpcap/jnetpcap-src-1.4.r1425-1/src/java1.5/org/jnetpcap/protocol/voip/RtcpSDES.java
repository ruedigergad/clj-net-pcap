/**
 * 
 */
package org.jnetpcap.protocol.voip;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * SDES: Source Description RTCP Packet
 * 
 * <p>
 * The SDES packet is a three-level structure composed of a header and zero or
 * more chunks, each of which is composed of items describing the source
 * identified in that chunk.
 * </p>
 * 
 * @author Sly Technologies Inc.
 * @since 1.4
 */
@Header(length = 4, name = "RTCP-SDES", suite = ProtocolSuite.TCP_IP)
public class RtcpSDES extends RtcpSSRC {

	/**
	 * SDES: Source Description RTCP Packet
	 */
	public final static int ID = JProtocol.RTCP_SDES_ID;

	public enum RtcpSDESType {

		/** End of Item list */
		NOP(0),

		/** CNAME: Canonical End-Point Identifier SDES Item */
		CNAME(1),

		/** NAME: User Name SDES Item */
		NAME(2),

		/** EMAIL: Electronic Mail Address SDES Item */
		EMAIL(3),

		/** PHONE: Phone Number SDES Item */
		PHONE(4),

		/** LOC: Geographic User Location SDES Item */
		LOC(5),

		/** TOOL: Application or Tool Name SDES Item */
		TOOL(6),

		/** NOTE: Notice/Status SDES Item */
		NOTE(7),

		/** PRIV: Private Extensions SDES Item */
		PRIV(8),

		;

		private final int type;

		private RtcpSDESType(int type) {
			this.type = type;
		}

		public static RtcpSDESType valueOf(int type) {
			for (RtcpSDESType t : values()) {
				if (t.type == type) {
					return t;
				}
			}

			return null;
		}
	}

	public static class RtcpSDESItem extends JBuffer {

		public static int readType(JBuffer buffer, int offset) {
			return buffer.getUByte(offset + 0);
		}

		public static int readLength(JBuffer buffer, int offset) {
			return buffer.getUByte(offset + 1);
		}

		private final int offset;
		private final int length;

		public int getOffset() {
			return offset;
		}

		public int getLength() {
			return length;
		}

		public RtcpSDESItem(JBuffer buffer, int offset, int length) {
			super(Type.POINTER);

			this.peer(buffer, offset, length);
			this.offset = offset;
			this.length = length;
		}

		public int type() {
			return super.getByte(0);
		}

		public RtcpSDESType typeEnum() {
			return RtcpSDESType.valueOf(type());
		}

		public int length() {
			return super.getByte(1);
		}

		public String value() {
			return super.getUTF8String(2, length());
		}

		public String toString() {

			return type() == 0 ? "NOP" : String.format("%s: %s", typeEnum()
					.toString(), value());
		}
	}

	public static class RtcpSDESChunk extends JBuffer {
		private final List<RtcpSDESItem> list = new ArrayList<RtcpSDESItem>(10);
		private int count = 0;

		public int getCount() {
			return count;
		}

		public void setCount(int count) {
			this.count = count;
		}

		public RtcpSDESChunk() {
			super(Type.POINTER);
		}

		public int ssrc() {
			return super.getInt(0);
		}

		public String toString() {
			return list.toString();
		}

	}

	/**
	 * source count (SC): 5 bits
	 * <p>
	 * The number of SSRC/CSRC chunks contained in this SDES packet. A value of
	 * zero is valid but useless.
	 * </p>
	 * 
	 * @return number of report blocks
	 */
	@Field(offset = 3, length = 5, display = "source count")
	public int sc() {
		return (super.getByte(0) & 0x1F) >> 0;
	}

	/**
	 * Gets the contents of all the Chunks within this SDES packet
	 * 
	 * @return array of chunk objects
	 */
	@Field(offset = 100, length = 4 * BYTE)
	public RtcpSDESChunk[] chunks() {
		return chunks(new RtcpSDESChunk[sc()]);
	}

	/**
	 * Gets the contents of all the Chunks within this SDES packet
	 * 
	 * @param chunks
	 *            array where to store chunk data, also allocates new chunk
	 *            objects for any array elements that are null otherwise
	 *            existing objects are reused and reinitialized
	 * @return array of chunk objects
	 */
	public RtcpSDESChunk[] chunks(RtcpSDESChunk[] chunks) {
		final int count = sc();
		int offset = 4;
		for (int i = 0; i < count && i < chunks.length; i++) {
			if (chunks[i] == null) {
				chunks[i] = new RtcpSDESChunk();
			}
			int len = readChunk(this, offset, chunks[i]);

			offset += len;
		}

		return chunks;
	}

	/**
	 * Reads and setups chunk objects
	 * 
	 * @param offset
	 *            start of this chunk with the packet
	 * @param chunk
	 *            a chunk object that will be initialized to point to chunk data
	 *            within buffer
	 * @return length of this chunk in bytes
	 */
	private int readChunk(JBuffer buffer, int start, RtcpSDESChunk chunk) {
		int chunkLength = 4;

		chunk.list.clear(); // Our setup storage

		int offset = start + 4;
		for (int i = 0; i < 255; i++) {
			int itemType = RtcpSDESItem.readType(buffer, offset);
			if (itemType == 0) {
				
				chunkLength = pad4(chunkLength);
				offset = pad4(offset);
				break;
			}
			
			int itemLen = RtcpSDESItem.readLength(buffer, offset);		

			if (offset + itemLen + 2 > buffer.size()) {
				System.out.printf("readChunk(): RTCP-SDES item: type=%d len=%d%n", itemType, itemLen);
				continue;
			}

			chunk.list.add(new RtcpSDESItem(buffer, offset, itemLen + 2));

			chunkLength += itemLen + 2;
			offset += itemLen + 2;

		}

		chunk.setCount(chunk.list.size());
		chunk.peer(buffer, start, chunkLength);

		return chunkLength;
	}

	private static int pad4(int value) {
		final int padded = value + ((4 - (value & 3)) & 3);

		return padded;
	}
}
