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
package org.jnetpcap;

import java.nio.ByteBuffer;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacket;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>pcap_dumper</code> structure. A dumper that
 * allows a previously opened pcap session to be dumped to a "savefile" which is
 * a file containing captured packets in pcap file format. To get an object of
 * type PcapDumper, use method <code>Pcap.dumpOpen</code>.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Library(preload = {Pcap.class}, jni = Pcap.LIBRARY)
public class PcapDumper {

	static {
		JNILibrary.register(PcapDumper.class);
	}

	/**
	 * Inits the i ds.
	 */
	@LibraryInitializer
	private static native void initIDs();

	/** The physical. */
	private volatile long physical;

	/**
	 * Closes a savefile. The existing PcapDumper object on which close method
	 * was invoked is no longer usable and needs to be discarded.
	 */
	public native void close();

	/**
	 * Writes the JMemoryPacket to 'savefile'
	 * 
	 * @param packet
	 *            any type of packet
	 * @since 1.4
	 */
	public void dump(JPacket packet) {
		dump(packet.getCaptureHeader(), packet);
	}

	/**
	 * Writes entire byte array to 'savefile'
	 * 
	 * @param seconds
	 *            timestamp in seconds
	 * @param useconds
	 *            fraction of second in micro-seconds
	 * @param wirelen
	 *            original length of the packet as if seen on the wire
	 * @param packet
	 *            packet buffer
	 * @since 1.4
	 */
	public void dump(long seconds, int useconds, int wirelen, byte[] packet) {
		dump(seconds, useconds, wirelen, packet, 0, packet.length);
	}

	/**
	 * Writes portion of the byte array to 'savefile'.
	 * 
	 * @param seconds
	 *            timestamp in seconds
	 * @param useconds
	 *            fraction of second in micro-seconds
	 * @param wirelen
	 *            original length of the packet as if seen on the wire
	 * @param packet
	 *            packet buffer
	 * @param offset
	 *            offset into packet buffer
	 * @param length
	 *            number of bytes to write
	 * @since 1.4
	 */
	public void dump(long seconds, int useconds, int wirelen, byte[] packet,
			int offset, int length) {
		dump0(seconds, useconds, wirelen, packet, offset, length);
	}

	private native void dump0(long seconds, int useconds, int wirelen,
			byte[] packet, int offset, int length);

	/**
	 * Outputs a packet to the "savefile" opened with <code>dumpOpen</code>.
	 * Note that the calling arguments are suitable for use with dipstach() or
	 * loop(). This a convenience method, which takes the parameters of
	 * PcapPkthdr class directly. This method ignores position and limit
	 * properties of the ByteBuffer.
	 * 
	 * @param seconds
	 *            timestamp in seconds
	 * @param useconds
	 *            timestamp fraction in microseconds
	 * @param caplen
	 *            how much was captured
	 * @param wirelen
	 *            actual packet length on wire
	 * @param packet
	 *            packet buffer
	 * 
	 * @deprecated This method ignores position and limit properties, use
	 *             {@link #dump(long, int, int, ByteBuffer)} instead
	 */
	public void dump(long seconds, int useconds, int caplen, int wirelen,
			ByteBuffer packet) {

		if (packet.hasArray()) {
			final byte[] data = packet.array();
			dump(seconds, useconds, wirelen, data, packet.arrayOffset(),
					packet.capacity());
		} else {
			dump1(seconds, useconds, caplen, packet, 0, packet.capacity());
		}
	}

	private native void dump1(long seconds, int useconds, int wirelen,
			ByteBuffer packet, int position, int limit);

	/**
	 * Writes packet data between position and limit properties to 'savefile'
	 * 
	 * @param seconds
	 *            timestamp in seconds
	 * @param useconds
	 *            timestamp fraction in microseconds
	 * @param wirelen
	 *            original length of the packet as if seen on the wire
	 * @param packet
	 *            packet buffer
	 */
	public void dump(long seconds, int useconds, int wirelen, ByteBuffer packet) {
		if (packet.hasArray()) {
			final byte[] data = packet.array();
			final int offset = packet.arrayOffset();
			dump(seconds, useconds, wirelen, data, offset + packet.position(),
					offset + packet.limit());
		} else {
			dump1(seconds, useconds, wirelen, packet, packet.position(),
					packet.limit());
		}
	}
	/**
	 * Writes entire contents of the buffer to 'savefile'.
	 * 
	 * @param seconds
	 *            timestamp in seconds
	 * @param useconds
	 *            timestamp fraction in microseconds
	 * @param wirelen
	 *            original length of the packet as if seen on the wire
	 * @param packet
	 *            packet buffer
	 * @since 1.4
	 */
	public void dump(long seconds, int useconds, int wirelen, JBuffer packet) {
		dump2(seconds, useconds, wirelen, packet, 0, packet.size());
	}

	/**
	 * Writes a portion of the packet buffer to 'savefile'
	 * 
	 * @param seconds
	 *            timestamp in seconds
	 * @param useconds
	 *            timestamp fraction in microseconds
	 * @param wirelen
	 *            original length of the packet as if seen on the wire
	 * @param packet
	 *            packet buffer
	 * @param offset
	 *            offset into packet buffer
	 * @param length
	 *            number of bytes to write
	 * @since 1.4
	 */
	public void dump(long seconds, int useconds, int wirelen, JBuffer packet,
			int offset, int length) {
		dump2(seconds, useconds, wirelen, packet, offset, length);
	}

	private native void dump2(long seconds, int useconds, int wirelen,
			JBuffer packet, int offset, int length);

	/**
	 * Outputs a packet to the "savefile" opened with <code>dumpOpen</code>.
	 * Note that the calling arguments are suitable for use with dipstach() or
	 * loop().
	 * 
	 * @param hdr
	 *            any capture header
	 * @param packet
	 *            packet buffer
	 * @since 1.2
	 */
	public void dump(JCaptureHeader hdr, ByteBuffer packet) {
		dump(hdr.seconds(), (int) hdr.nanos() / 1000, hdr.wirelen(), packet);
	}

	/**
	 * Outputs a packet to the "savefile" opened with <code>dumpOpen</code>.
	 * Note that the calling arguments are suitable for use with dipstach() or
	 * loop().
	 * 
	 * @param hdr
	 *            any capture header
	 * @param packet
	 *            packet buffer
	 * @since 1.2
	 */
	public void dump(JCaptureHeader hdr, JBuffer packet) {
		dump(hdr.seconds(), (int) hdr.nanos() / 1000, hdr.wirelen(), packet);
	}

	/**
	 * Outputs a packet to the "savefile" opened with <code>dumpOpen</code>.
	 * Note that the calling arguments are suitable for use with dipstach() or
	 * loop().
	 * 
	 * @param hdr
	 *            pcap capture header
	 * @param packet
	 *            packet buffer
	 * @deprecated use of PcapPktHdr has been replaced by PcapHeader
	 * @see PcapHeader
	 */
	@Deprecated
	public void dump(PcapPktHdr hdr, ByteBuffer packet) {
		dump(hdr.getSeconds(), hdr.getUseconds(), hdr.getCaplen(),
				hdr.getLen(), packet);
	}

	/**
	 * Flushes the output buffer to the "savefile", so that any packets written
	 * with <code>Pcap.dump</code> but not yet written to the "savefile" will be
	 * written.
	 * 
	 * @return 0 on success, -1 on error
	 */
	public native int flush();

	/**
	 * Returns the current file position for the "savefile", representing the
	 * number of bytes written by <code>Pcap.dumpOpen</code> and
	 * <code>Pcap.dump</code>.
	 * 
	 * @return position within the file, or -1 on error
	 */
	public native long ftell();

}
