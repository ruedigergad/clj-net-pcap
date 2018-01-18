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
package org.jnetpcap.protocol.aaa;

import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.sigtran.Sctp;
import org.jnetpcap.protocol.sigtran.SctpData;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.util.JThreadLocal;

// TODO: Auto-generated Javadoc
/**
 * The Class Diameter.
 */
@Header(length = 20)
public class Diameter extends JHeaderMap<Diameter> {

	/** The ID. */
	public static int ID;

	static {
		try {
			ID = JRegistry.register(Diameter.class);
		} catch (final RegistryHeaderErrors e) {
			e.printStackTrace();
		}
	}

	/**
	 * Bind to tcp.
	 * 
	 * @param packet
	 *            the packet
	 * @param tcp
	 *            the tcp
	 * @return true, if successful
	 */
	@Bind(to = Tcp.class)
	public static boolean bindToTcp(JPacket packet, Tcp tcp) {
		return tcp.destination() == 3868 || tcp.source() == 3868;
	}

	private final static JThreadLocal<Sctp> local = new JThreadLocal<Sctp>(
			Sctp.class);

	@Bind(to = SctpData.class)
	public static boolean bindToTcp(JPacket packet, SctpData data) {
		final Sctp sctp = local.get();
		return packet.hasHeader(sctp)
				&& (sctp.destination() == 3868 || sctp.source() == 3868);
	}

	/**
	 * Header length.
	 * 
	 * @param buffer
	 *            the buffer
	 * @param offset
	 *            the offset
	 * @return the int
	 */
	// @HeaderLength
	// public static int headerLength(JBuffer buffer, int offset) {
	// return (int) buffer.getUInt(offset) & 0x00FFFFFF;
	// }

	// Diameter header accessors
	/**
	 * Gets the version.
	 * 
	 * @return the version
	 */
	@Field(offset = 0, length = 8, format = "%d", display = "version")
	public int getVersion() {
		return super.getUByte(0);
	}

	/**
	 * Gets the message length.
	 * 
	 * @return the message length
	 */
	@Field(offset = 8, length = 24, format = "%d", display = "length")
	public int getMessageLength() {
		return (int) super.getUInt(0) & 0x00FFFFFF;
	}

	/**
	 * Gets the command flags.
	 * 
	 * @return the command flags
	 */
	@Field(offset = 4 * BYTE, length = 8, format = "%x", display = "flags")
	public int getCommandFlags() {
		return super.getUByte(4);
	}

	/**
	 * Gets the command code.
	 * 
	 * @return the command code
	 */
	@Field(offset = 5 * BYTE, length = 24, format = "%x", display = "code")
	public int getCommandCode() {
		return (int) super.getUInt(4) & 0x00FFFFFF;
	}

	@Field(offset = 8 * 8, length = 4 * 8, format = "%d", display = "Application-ID")
	public int applicationID() {
		return (int) super.getUInt(8);
	}

	@Field(offset = 12 * BYTE, length = 32, format = "%x", display = "Hop-by-Hop Identifier")
	public int getHopByHopIdentifier() {
		return super.getInt(12);
	}
	@Field(offset = 16 * BYTE, length = 32, format = "%x", display = "End-to-End Identifier")
	public int getEndToEndIdentifier() {
		return super.getInt(16);
	}
}