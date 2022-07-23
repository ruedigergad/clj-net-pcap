/**
 * 
 */
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * BYE: Goodbye RTCP Packet
 * 
 * <p>
 * The BYE packet indicates that one or more sources are no longer active.
 * </p>
 * 
 * @author Sly Technologies Inc.
 * @since 1.4
 */
@Header(length = 4, name = "RTCP-BYE", suite = ProtocolSuite.TCP_IP)
public class RtcpBye extends Rtcp {

	/**
	 * BYE: Goodbye RTCP Packet
	 */
	public final static int ID = JProtocol.RTCP_BYE_ID;

	/**
	 * source count (SC): 5 bits
	 * <p>
	 * The number of SSRC/CSRC identifiers included in this BYE packet. A count
	 * value of zero is valid, but useless.
	 * </p>
	 * 
	 * @return number of source blocks
	 */
	@Field(offset = 3, length = 5, display = "source count")
	public int sc() {
		return (super.getByte(0) & 0x1F) >> 0;
	}

	@Dynamic(field = "ssrc", value = Field.Property.LENGTH)
	public int ssrcLength() {
		return sc() * (4 * BYTE);
	}

	/**
	 * Array of sources that are no longer active
	 * 
	 * @return array of source IDs
	 */
	@Field(offset = 4 * BYTE, length = 4 * BYTE, format = "%x")
	public int[] ssrc() {
		return ssrc(new int[sc()]);
	}

	/**
	 * Array of sources that are no longer active. The values are read into
	 * existing array.
	 * 
	 * @param array
	 *            array where to store SSRC identifiers
	 * @return the array that was passed in
	 */
	public int[] ssrc(int[] array) {
		final int count = sc();

		for (int i = 0; i < count && i < array.length; i++) {
			array[i] = super.getInt(4 + (i * 4));
		}

		return array;
	}

	@Dynamic(field = "reason", value = Field.Property.CHECK)
	public boolean hasReason() {
		int len = (super.length() << 2) + 4;

		return len > (sc() * 4 + 4);
	}

	@Dynamic(field = "reason", value = Field.Property.OFFSET)
	public int reasonOffset() {
		return ((sc() << 2) + 4) * BYTE;
	}

	@Dynamic(field = "reason", value = Field.Property.LENGTH)
	public int reasonBitLength() {
		return reasonLength() * BYTE;
	}

	/**
	 * 8-bit octet count of number of characters
	 * 
	 * @return length of the, possibly null padded, reason string
	 */
	public int reasonLength() {
		final int offset = (sc() << 2) + 4;
		return super.getUByte(offset);
	}

	/**
	 * Text indicating the reason for leaving, e.g., "camera
	 * malfunction" or "RTP loop detected"
	 * 
	 * @return text indicating the reason
	 */
	@Field
	public String reason() {
		if (!hasReason()) {
			return "";
		}

		final int offset = (sc() << 2) + 4;

		int len = super.getUByte(offset); // Length of string
		boolean isPadded = (len & 3) != 0; // If padded null terminated,
											// otherwise exact len

		if (isPadded) {
			return super.getUTF8String(offset + 1, '\u0000');
		} else {
			return super.getUTF8String(offset + 1, len);
		}
	}
}
