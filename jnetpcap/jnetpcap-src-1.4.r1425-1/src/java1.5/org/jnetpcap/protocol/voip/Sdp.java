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
package org.jnetpcap.protocol.voip;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JMappedHeader;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Session Description Protocol (SDP) is a format for describing streaming
 * media initialization parameters. The IETF published the original
 * specification as an IETF Proposed Standard in April 1998,[1] and subsequently
 * published a revised specification as an IETF Proposed Standard as RFC 4566 in
 * July 2006.[2]
 * <p>
 * SDP is intended for describing multimedia communication sessions for the
 * purposes of session announcement, session invitation, and parameter
 * negotiation. SDP does not deliver media itself but is used for negotiation
 * between end points of media type, format, and all associated properties. The
 * set of properties and parameters are often called a session profile. SDP is
 * designed to be extensible to support new media types and formats.
 * </p>
 * <p>
 * SDP started off as a component of the Session Announcement Protocol (SAP),
 * but found other uses in conjunction with Real-time Transport Protocol (RTP),
 * Real-time Streaming Protocol (RTSP), Session Initiation Protocol (SIP) and
 * even as a standalone format for describing multicast sessions.
 * </p>
 * <p>
 * Description source: http://en.wikipedia.org/wiki/Session_Description_Protocol
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
public class Sdp
    extends
    JMappedHeader {

	/**
	 * A table of various fields for SDP protocol.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Field
	public enum Fields {
		
		/** Connection info field. */
		ConnectionInfo,
		
		/** Media field. */
		Media,
		
		/** Owner field. */
		Owner,
		
		/** Session name field. */
		SessionName,

		/** Time field. */
		Time,

		/** Version field. */
		Version
	}

	/** Constant numerial ID for this protocol's header. */
	public static int ID = JProtocol.SDP_ID;

	static {
		try {
			ID = JRegistry.register(Sdp.class);
		} catch (final RegistryHeaderErrors e) {
			e.printStackTrace();
		}
	}

	/**
	 * Calculates the length of this header from a static context.
	 * 
	 * @param buffer
	 *          buffer containing the packet or this header content
	 * @param offset
	 *          offset into the buffer where this header begins
	 * @return length in bytes for this header, excluding payload
	 */
	@HeaderLength
	public static int headerLength(final JBuffer buffer, final int offset) {
		return buffer.size() - offset;
	}

	/** The attributes. */
	private String[] attributes;

	/** The attributes length. */
	private int attributesLength;

	/** The attributes offset. */
	private int attributesOffset;

	/** The text. */
	private String text;

	/**
	 * Returns as array of Strings with all the attributes of this message.
	 * 
	 * @return array containing all the attributes found in this message
	 */
	@Field(offset = 0, length = 10, format = "%s[]")
	public String[] attributes() {
		return this.attributes;
	}

	/**
	 * Returns the length of the 'attributes' field.
	 * 
	 * @return length of the 'attributes' field; the length is in bits
	 */
	@Dynamic(Field.Property.LENGTH)
	public int attributesLength() {
		return this.attributesLength;
	}

	/**
	 * Returns the offset into the header for the 'attributes' field.
	 * 
	 * @return offset from the start of the header; the offset is in bits
	 */
	@Dynamic(Field.Property.OFFSET)
	public int attributesOffset() {
		return this.attributesOffset;
	}

	/**
	 * Decode header.
	 * 
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {
		this.text = super.getUTF8String(0, size());

		final String[] lines = this.text.split("\r\n");
		final List<String> list = new ArrayList<String>(10);

		int offset = 0;
		for (String line : lines) {
			final char firstChar = line.charAt(0);
			line = line.substring(2).trim();
			final int length = line.length() * 8;

			// System.out.printf("line='%s'\n", line);

			switch (firstChar) {
				case 'v':
					super.addField(Fields.Version, line, offset, length);
					break;

				case 'o':
					super.addField(Fields.Owner, line, offset, length);
					break;

				case 's':
					super.addField(Fields.SessionName, line, offset, length);
					break;

				case 'c':
					super.addField(Fields.ConnectionInfo, line, offset, length);
					break;

				case 't':
					super.addField(Fields.Time, line, offset, length);
					break;

				case 'm':
					super.addField(Fields.Media, line, offset, length);
					break;

				case 'a':
					list.add(line);
					break;
			}

			offset += (line.length() + 2) * 8;
		}
		this.attributesOffset = offset;
		this.attributesLength = (size() - offset / 8) * 8;
		this.attributes = list.toArray(new String[list.size()]);
	}

	/**
	 * Experimental function.
	 * 
	 * @return the entire SDP header as a text string
	 */
	// @Field(offset = 0, format="#textdump#")
	public String text() {
		return this.text;
	}

	/**
	 * Experimental function.
	 * 
	 * @return size of the SDP header in bits
	 */
	// @Dynamic(Field.Property.LENGTH)
	public int textLength() {
		return size() * 8;
	}
}
