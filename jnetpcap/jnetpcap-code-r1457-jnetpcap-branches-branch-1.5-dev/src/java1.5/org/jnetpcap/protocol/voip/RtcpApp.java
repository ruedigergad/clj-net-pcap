/**
 * 
 */
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * APP: Application-Defined RTCP Packet
 * 
 * <p>
 * The APP packet is intended for experimental use as new applications and new
 * features are developed, without requiring packet type value registration. APP
 * packets with unrecognized names SHOULD be ignored. After testing and if wider
 * use is justified, it is RECOMMENDED that each APP packet be redefined without
 * the subtype and name fields and registered with IANA using an RTCP packet
 * type.
 * </p>
 * 
 * @author Sly Technologies Inc.
 * @since 1.4
 */
@Header(length = 4, name = "RTCP-APP", suite = ProtocolSuite.TCP_IP)
public class RtcpApp extends Rtcp {

	/**
	 *  APP: Application-Defined RTCP Packet
	 */
	public final static int ID = JProtocol.RTCP_APP_ID;


	/**
	 * subtype: 5 bits
	 * 
	 * <p>
	 * May be used as a subtype to allow a set of APP packets to be defined
	 * under one unique name, or for any application-dependent data.
	 * </p>
	 * 
	 * @return number of source blocks
	 */
	@Field(offset = 3, length = 5, display = "source count")
	public int subtype() {
		return super.getUByte(0) >> 3;
	}

	/**
	 * name: 4 octets
	 * <p>
	 * A name chosen by the person defining the set of APP packets to be unique
	 * with respect to other APP packets this application might receive. The
	 * application creator might choose to use the application name, and then
	 * coordinate the allocation of subtype values to others who want to define
	 * new packet types for the application. Alternatively, it is RECOMMENDED
	 * that others choose a name based on the entity they represent, then
	 * coordinate the use of the name within that entity. The name is
	 * interpreted as a sequence of four ASCII characters, with uppercase and
	 * lowercase characters treated as distinct.
	 * </p>
	 * 
	 * @return
	 */
	@Field(offset = 8 * BYTE, length = 4 * BYTE, display = "name")
	public String name() {
		return super.getUTF8String(8, 4);
	}

}
