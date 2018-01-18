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
package org.jnetpcap.protocol.network;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.tcpip.Udp;

// TODO: Auto-generated Javadoc
/**
 * Routing Information Protocol (RIP). This is a baseclass for subclasses Rip1
 * and Rip2 which parse rip version 1 and version 2 protocols.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(suite = ProtocolSuite.TCP_IP, description = "Routing Information Protocol")
public abstract class Rip extends JHeader {

	/**
	 * Valid values for RIP OpCode field.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Command {

		/** The REQUEST. */
		REQUEST,

		/** The REPLY. */
		REPLY,

		/** The TRAC e_ on. */
		TRACE_ON,

		/** The TRAC e_ off. */
		TRACE_OFF,

		/** The SUN. */
		SUN,

		/** The TRIGGERE d_ request. */
		TRIGGERED_REQUEST,

		/** The TRIGGERE d_ response. */
		TRIGGERED_RESPONSE,

		/** The TRIGGERE d_ ack. */
		TRIGGERED_ACK,

		/** The UPDAT e_ request. */
		UPDATE_REQUEST,

		/** The UPDAT e_ response. */
		UPDATE_RESPONSE,

		/** The UPDAT e_ ack. */
		UPDATE_ACK;

		/**
		 * Value of.
		 * 
		 * @param value
		 *          the value
		 * @return the command
		 */
		public static Command valueOf(final int value) {
			return (value < values().length) ? values()[value] : null;
		}
	}

	/**
	 * Bind to UDP port 520 which is the default for RIP.
	 * 
	 * @param packet
	 *          current packet
	 * @param udp
	 *          udp header within this packet
	 * @return true if binding succeeded or false if failed
	 */
	@Bind(to = Udp.class)
	public static boolean bindToUdp(final JPacket packet,
			final org.jnetpcap.protocol.tcpip.Udp udp) {
		return (udp.destination() == 520) || (udp.source() == 520);
	}

	/**
	 * Header length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	@HeaderLength
	public static int headerLength(final JBuffer buffer, final int offset) {
		return buffer.size() - offset;
	}

	/** The count. */
	protected int count;

	/**
	 * Command.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, length = 8)
	public int command() {
		return super.getUByte(0);
	}

	/**
	 * Command description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String commandDescription() {
		return commandEnum().toString();
	}

	/**
	 * Command enum.
	 * 
	 * @return the command
	 */
	public Command commandEnum() {
		return Command.valueOf(command());
	}

	/**
	 * Gets the number of entries in the routing table.
	 * 
	 * @return count of number of 20 byte entries in the routing table
	 */
	public int count() {
		return this.count;
	}

	/**
	 * The routing table is the only thing that needs decoding. The routing table
	 * is lazy decoded.
	 */
	@Override
	protected void decodeHeader() {
		this.count = (size() - 4) / 20;
	}

	/**
	 * Version.
	 * 
	 * @return the int
	 */
	@Field(offset = 8, length = 8)
	public int version() {
		return super.getUByte(1);
	}

}
