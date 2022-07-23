/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap.extension;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;

/**
 * Pcap extension with expanded capture capabilities.
 *
 * @author Sly Technologies Inc.
 */
public class PcapExtension extends Pcap {

	/**
	 * Peer to existing pcap handle.
	 *
	 * @param pcap
	 *            the pcap
	 * @return the pcap extension
	 */
	static PcapExtension from(Pcap pcap) {
		PcapExtension ext = new PcapExtension();

		PcapExtension.peer(pcap, ext);

		return ext;
	}

	/**
	 * Peer Pcap object's physical pcap handle address to PcapExtension object.
	 *
	 * @param pcap
	 *            the pcap source
	 * @param ext
	 *            the ext destination
	 */
	private native static void peer(Pcap pcap, PcapExtension ext);

	/**
	 * Instantiates a new pcap extension.
	 */
	PcapExtension() {
	}

	/**
	 * Dispatch multiple packets to buffer.
	 *
	 * @param cnt
	 *            the number of packets to dispatch or 0 for unlimited
	 * @param buffer
	 *            the buffer where to store captured packets
	 * @param capacity
	 *            TODO
	 * @param off
	 *            the offset into the buffer where to store the first packet
	 * @param descrLen
	 *            The length in octets of the descriptor preceding each packet.
	 *            The pcap header descriptor takes up the initial 16 bytes while
	 *            any additional space is left empty and uninitialized in the
	 *            buffer.
	 * @return result of the dispatch operation where a positive number is
	 *         number of packets and a -1 an error
	 */
	public native int dispatchToBuffer(int cnt, JBuffer buffer, int capacity, int off, int descrLen);

	/**
	 * Dispatch multiple packets to byte array buffer.
	 *
	 * @param cnt
	 *            the number of packets to dispatch or 0 for unlimited
	 * @param buffer
	 *            the buffer where to store captured packets
	 * @param off
	 *            the offset into the buffer where to store the first packet
	 * @param descrLen
	 *            The length in octets of the descriptor preceding each packet.
	 *            The pcap header descriptor takes up the initial 16 bytes while
	 *            any additional space is left empty and uninitialized in the
	 *            buffer.
	 * @return result of the dispatch operation where a positive number is
	 *         number of packets and a -1 an error
	 */
	public native int dispatchToByteArray(int cnt, byte[] buffer, int off, int descrLen);

}
