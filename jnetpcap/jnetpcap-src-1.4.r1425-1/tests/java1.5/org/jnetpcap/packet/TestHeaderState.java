/**
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

import java.lang.ref.WeakReference;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.protocol.lan.Ethernet;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * 
 */
public class TestHeaderState extends TestUtils {

	final JHeader.State headerState = new JHeader.State(JMemory.POINTER);
	private static WeakReference<JPcapRecordBuffer> bufferRef = null;

	protected JPcapRecordBuffer getBuffer() {
		if (bufferRef == null || bufferRef.get() == null) {
			bufferRef = new WeakReference<JPcapRecordBuffer>(loadAllTestPackets());
		}

		return bufferRef.get();
	}

	public void testRawHeaderdBounds() {
		JPcapRecordBuffer buffer = getBuffer();

		buffer.dispatchToJBuffeHandler(new JBufferHandler<String>() {

			@Override
			public void nextPacket(PcapHeader header, JBuffer buffer, String user) {
				PcapPacket packet = new PcapPacket(header, buffer);
				packet.scan(Ethernet.ID);

				final JPacket.State packetState = packet.getState();
				for (int index = 0; index < packetState.getHeaderCount(); index++) {
					int start = packetState.getHeaderOffsetByIndex(index);
					int length = packetState.getHeaderLengthByIndex(index);
					packet.getByteArray(start, length);
				}

			}
		}, "");

	}

	public void testRawHeaderPropertyAccessAndBounds() {
		JPcapRecordBuffer buffer = getBuffer();

		out = DISCARD;

		buffer.dispatchToJBuffeHandler(new JBufferHandler<String>() {

			@Override
			public void nextPacket(PcapHeader header, JBuffer buffer, String user) {
				PcapPacket packet = new PcapPacket(header, buffer);
				packet.scan(Ethernet.ID);

				final JPacket.State packetState = packet.getState();
				for (int index = 0; index < packetState.getHeaderCount(); index++) {
					int id = packetState.getHeaderIdByIndex(index);

					packetState.peerHeaderByIndex(index, headerState);

					int start = headerState.getOffset();
					int pre = headerState.getPrefix();
					int hdr = headerState.getLength();
					int gap = headerState.getGap();
					int pay = headerState.getPayload();
					int post = headerState.getPostfix();

					if (out != DISCARD)
						out.printf("#%d.%d(%d):: packet.size=%d start=%d "
								+ "pre=%d hdr=%d gap=%d pay=%d post=%d%n",
								packet.getFrameNumber(),
								index,
								id,
								packet.size(),
								start,
								pre,
								hdr,
								gap,
								pay,
								post);

					packet.getByteArray(start - pre, pre);
					packet.getByteArray(start, hdr);
					packet.getByteArray(start + hdr, gap);
					packet.getByteArray(start + hdr + gap, pay);
					packet.getByteArray(start + hdr + gap + pay, post);
				}

			}
		},
				"");

	}

	public void testJHeaderPropertyAccessAndBounds() {
		final JPcapRecordBuffer buffer = getBuffer();

		final JHeaderPool headers = new JHeaderPool();

		out = DISCARD;

		buffer.dispatchToJBuffeHandler(new JBufferHandler<String>() {

			@Override
			public void nextPacket(PcapHeader header, JBuffer buffer, String user) {
				PcapPacket packet = new PcapPacket(header, buffer);
				packet.scan(Ethernet.ID);

				final JPacket.State packetState = packet.getState();
				for (int index = 0; index < packetState.getHeaderCount(); index++) {
					int id = packetState.getHeaderIdByIndex(index);
					final JHeader hdr = headers.getHeader(id);
					packet.getHeaderByIndex(index, hdr);

					if (out != DISCARD)
						out.printf("#%d.%d(%d):: packet.size=%d start=%d length=%d "
								+ "pre=%d hdr=%d gap=%d pay=%d post=%d%n",
								packet.getFrameNumber(),
								index,
								id,
								packet.size(),
								hdr.getOffset(),
								hdr.getLength(),
								hdr.getPrefixOffset(),
								hdr.getOffset(),
								hdr.getGapOffset(),
								hdr.getPayloadOffset(),
								hdr.getPostfixOffset());

					packet.getByteArray(hdr.getPrefixOffset(), hdr.getPrefixLength());
					packet.getByteArray(hdr.getOffset(), hdr.getLength());
					packet.getByteArray(hdr.getGapOffset(), hdr.getGapLength());
					packet.getByteArray(hdr.getPayloadOffset(), hdr.getPayloadLength());
					packet.getByteArray(hdr.getPostfixOffset(), hdr.getPostfixLength());
				}

			}
		},
				"");

	}
}
