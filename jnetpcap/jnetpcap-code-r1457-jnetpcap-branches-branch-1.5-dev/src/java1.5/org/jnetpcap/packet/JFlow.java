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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

// TODO: Auto-generated Javadoc
/**
 * The Class JFlow.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JFlow {

	/** The key. */
	private final JFlowKey key;

	/** The reversable. */
	private final boolean reversable;

	/** The all. */
	private final List<JPacket> all;

	/** The forward. */
	private final List<JPacket> forward;

	/** The reverse. */
	private final List<JPacket> reverse;

	/**
	 * Instantiates a new j flow.
	 * 
	 * @param key
	 *          the key
	 */
	public JFlow(JFlowKey key) {
		this.key = key;
		this.reversable = (key.getFlags() & JFlowKey.FLAG_REVERSABLE) > 0;

		if (this.reversable) {
			this.all = new LinkedList<JPacket>();
			this.forward = new LinkedList<JPacket>();
			this.reverse = new LinkedList<JPacket>();
		} else {
			this.all = new LinkedList<JPacket>();
			this.forward = Collections.emptyList();
			this.reverse = Collections.emptyList();
		}
	}

	/**
	 * Gets the key.
	 * 
	 * @return the key
	 */
	public final JFlowKey getKey() {
		return this.key;
	}

	/**
	 * Adds the.
	 * 
	 * @param packet
	 *          the packet
	 * @return true, if successful
	 */
	public boolean add(JPacket packet) {
		int dir = key.match(packet.getState().getFlowKey());
		if (dir == 0) {
			return false;
		}

		if (this.isReversable() == false) {
			return this.all.add(packet);
		}

		return ((dir == 1) ? forward.add(packet) : reverse.add(packet))
				&& all.add(packet);
	}

	/**
	 * Checks if is reversable.
	 * 
	 * @return the reversable
	 */
	public final boolean isReversable() {
		return this.reversable;
	}

	/**
	 * Gets the all.
	 * 
	 * @return the all
	 */
	public final List<JPacket> getAll() {
		return this.all;
	}

	/**
	 * Size.
	 * 
	 * @return the int
	 */
	public int size() {
		return all.size();
	}

	/**
	 * Gets the forward.
	 * 
	 * @return the forward
	 */
	public final List<JPacket> getForward() {
		return (this.reversable) ? this.forward : this.all;
	}

	/**
	 * Gets the reverse.
	 * 
	 * @return the reverse
	 */
	public final List<JPacket> getReverse() {
		return (this.reversable) ? this.reverse : null;
	}

	/** The tcp. */
	private final Tcp tcp = new Tcp();

	/** The ip. */
	private final Ip4 ip = new Ip4();

	/** The eth. */
	private final Ethernet eth = new Ethernet();

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (all.isEmpty()) {
			return key.toDebugString() + " size=" + all.size();
		}

		JPacket packet = all.get(0);
		if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {
			String dst = FormatUtils.ip(ip.destination());
			String src = FormatUtils.ip(ip.source());
			String sport = "" + tcp.source();
			String dport = "" + tcp.destination();
			// String hash = Integer.toHexString(key.hashCode());

			return src + ":" + sport + " -> " + dst + ":" + dport
					+ " Tcp fw/rev/tot pkts=[" + forward.size() + "/" + reverse.size()
					+ "/" + all.size() + "]";

		} else if (packet.hasHeader(ip)) {
			String dst = FormatUtils.ip(ip.destination());
			String src = FormatUtils.ip(ip.source());
			String type = "" + ip.type();

			return src + " -> " + dst + ":" + type + " Ip4 tot pkts=[" + all.size()
					+ "]";

		} else if (packet.hasHeader(eth)) {
			String dst = FormatUtils.mac(eth.destination());
			String src = FormatUtils.mac(eth.source());
			String type = Integer.toHexString(eth.type());

			return src + " -> " + dst + ":" + type + " Eth tot pkts=[" + all.size()
					+ "]";

		} else {
			return key.toDebugString() + " packets=" + all.size();
		}
	}
}
