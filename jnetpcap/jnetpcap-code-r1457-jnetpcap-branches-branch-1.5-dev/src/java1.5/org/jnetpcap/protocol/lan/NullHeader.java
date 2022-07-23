/**
 * 
 */
package org.jnetpcap.protocol.lan;

import java.nio.ByteOrder;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;

/**
 * BSD loopback encapsulation; the link-layer header is a 4-byte field, in host
 * byte order, containing a PF_ value from socket.h for the network-layer
 * protocol of the packet.
 * <p>
 * Note that ''host byte order'' is the byte order of the machine on which the
 * packets are captured, and the PF_ values are for the OS of the machine on
 * which the packets are captured; if a live capture is being done, ''host byte
 * order'' is the byte order of the machine capturing the packets, and the PF_
 * values are those of the OS of the machine capturing the packets, but if a
 * ''savefile'' is being read, the byte order and PF_ values are not necessarily
 * those of the machine reading the capture file.
 * </p>
 * 
 * @author Sly Technologies Inc.
 * @see http://linux.die.net/man/7/pcap-linktype
 */
@Header(length = 4, dlt = PcapDLT.NULL, osi = Header.Layer.DATALINK, nicname = "Null")
public class NullHeader extends JHeader {

	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.NULL_HEADER_ID;

	/**
	 * Creates a default NullHeader object, that first assumes a LITTLE_ENDIAN
	 * byte encoding. The header byte-order is also checked at runtime during
	 * "binding" process but LITTLE_ENDIAN is assumed first and more efficient
	 * at performing the check.
	 */
	public NullHeader() {
		super();
		order(ByteOrder.LITTLE_ENDIAN);
	}

	/**
	 * Next Protocol type as defined by PF_ values in socket.h file on local
	 * system. I.e. 2 = IP4
	 * 
	 * @return the protocol value
	 */
	@Field(offset = 0, length = 4 * BYTE, display = "PF_ Value")
	public int family() {
		return super.getInt(0);
	}

	/**
	 * Next Protocol type as defined by PF_ values in socket.h file on local
	 * system
	 * 
	 * @param value
	 *            the protocol value
	 */
	public void family(int value) {
		super.setInt(0, value);
	}

	/**
	 * We use the decoder to check the byte-order of the NullHeader and set
	 * byte-order appropriately on the header.
	 */
	@Override
	protected void decodeHeader() {

		/*
		 * We use the fact that there are no PF_ values greater then just a few.
		 * So if we are too big on default LITTLE_ENDIAN encoding, we switch to
		 * big. We start with LITTLE since this is most of the machines we run
		 * on
		 */
		if (family() > 0x01000000 || family() < 0) {
			if (order() == ByteOrder.LITTLE_ENDIAN) {
				order(ByteOrder.BIG_ENDIAN);
			} else {
				order(ByteOrder.LITTLE_ENDIAN);
			}
		}

		super.decodeHeader();
	}

}
