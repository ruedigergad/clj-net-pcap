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
package org.jnetpcap.protocol.tcpip;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * Hyper Text Transfer Protocol header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(suite = ProtocolSuite.TCP_IP)
public class Http
    extends
    AbstractMessageHeader {

	/** Constant numerical ID assigned to this protocol. */
	public final static int ID = JProtocol.HTTP_ID;

	/**
	 * Http content type table.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum ContentType {
		
		/** The GIF. */
		GIF("image/gif"),
		
		/** The HTML. */
		HTML("text/html"),
		
		/** The JPEG. */
		JPEG("image/jpeg"),
		
		/** The PNG. */
		PNG("image/png"),
		
		/** The OTHER. */
		OTHER, ;

		/**
		 * Parses the content type.
		 * 
		 * @param type
		 *          the type
		 * @return the content type
		 */
		public static ContentType parseContentType(String type) {
			if (type == null) {
				return OTHER;
			}

			for (ContentType t : values()) {
				if (t.name().equalsIgnoreCase(type)) {
					return t;
				}

				for (String m : t.magic) {
					if (type.startsWith(m)) {
						return t;
					}
				}
			}

			return OTHER;
		}

		/** The magic. */
		private final String[] magic;

		/**
		 * Instantiates a new content type.
		 * 
		 * @param magic
		 *          the magic
		 */
		private ContentType(String... magic) {
			this.magic = magic;
		}
	}

	/**
	 * HTTP Request fields.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Field
	public enum Request {
		
		/** The Accept. */
		Accept,
		
		/** The Accept_ charset. */
		Accept_Charset,
		
		/** The Accept_ encoding. */
		Accept_Encoding,
		
		/** The Accept_ ranges. */
		Accept_Ranges,
		
		/** The Accept_ language. */
		Accept_Language,
		
		/** The U a_ cpu. */
		UA_CPU,
		
		/** The Proxy_ connection. */
		Proxy_Connection,
		
		/** The Authorization. */
		Authorization,
		
		/** The Cache_ control. */
		Cache_Control,
		
		/** The Connection. */
		Connection,
		
		/** The Cookie. */
		Cookie,
		
		/** The Date. */
		Date,
		
		/** The Host. */
		Host,
		
		/** The If_ modified_ since. */
		If_Modified_Since,
		
		/** The If_ none_ match. */
		If_None_Match,
		
		/** The Referer. */
		Referer,
		
		/** The Request method. */
		RequestMethod,

		/** The Request url. */
		RequestUrl,
		
		/** The Request version. */
		RequestVersion,
		
		/** The User_ agent. */
		User_Agent,

		/** The Content_ length. */
		Content_Length,
		
		/** The Content_ type. */
		Content_Type,
	}

	/**
	 * HTTP Response fields.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Field
	public enum Response {
		
		/** The Accept_ ranges. */
		Accept_Ranges,
		
		/** The Age. */
		Age,
		
		/** The Allow. */
		Allow,
		
		/** The Cache_ control. */
		Cache_Control,
		
		/** The Content_ disposition. */
		Content_Disposition,
		
		/** The Content_ encoding. */
		Content_Encoding,
		
		/** The Content_ length. */
		Content_Length,
		
		/** The Content_ location. */
		Content_Location,
		
		/** The Content_ m d5. */
		Content_MD5,
		
		/** The Content_ range. */
		Content_Range,
		
		/** The Content_ type. */
		Content_Type,
		
		/** The Expires. */
		Expires,
		
		/** The Server. */
		Server,
		
		/** The Set_ cookie. */
		Set_Cookie,

		/** The Request url. */
		RequestUrl,
		
		/** The Request version. */
		RequestVersion,
		
		/** The Response code. */
		ResponseCode,
		
		/** The Response code msg. */
		ResponseCodeMsg,
	}

	/**
	 * Content type.
	 * 
	 * @return the string
	 */
	public String contentType() {
		return fieldValue(Response.Content_Type);
	}

	/**
	 * Content type enum.
	 * 
	 * @return the content type
	 */
	public ContentType contentTypeEnum() {
		return ContentType.parseContentType(contentType());
	}

	/**
	 * A http chunk that has been encoded during transfer as "Transfer-Encoding:
	 * chuncked".
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class Chunk
	    extends
	    JBuffer {

		/**
		 * Instantiates a new chunk.
		 * 
		 * @param type
		 *          the type
		 */
		public Chunk(Type type) {
			super(type);
		}

	}

	/**
	 * Checks for chuncks.
	 * 
	 * @return true, if successful
	 */
	public boolean hasChuncks() {
		return false;
	}

	/**
	 * Chunks.
	 * 
	 * @return the chunk[]
	 */
	public Chunk[] chunks() {
		return new Chunk[0];
	}

	/**
	 * Decode first line.
	 * 
	 * @param line
	 *          the line
	 * @see org.jnetpcap.packet.AbstractMessageHeader#decodeFirstLine(java.lang.String)
	 */
	@Override
	protected void decodeFirstLine(String line) {
		// System.out.printf("#%d Http::decodeFirstLine line=%s\n", getPacket()
		// .getFrameNumber(), line);
		String[] c = line.split(" ");
		if (c.length < 3) {
			return; // Can't parse it
		}

		if (c[0].startsWith("HTTP")) {
			super.setMessageType(MessageType.RESPONSE);

			super.addField(Response.RequestVersion, c[0], line.indexOf(c[0]));
			super.addField(Response.ResponseCode, c[1], line.indexOf(c[1]));
			super.addField(Response.ResponseCodeMsg, c[2], line.indexOf(c[2]));

		} else {
			super.setMessageType(MessageType.REQUEST);

			super.addField(Request.RequestMethod, c[0], line.indexOf(c[0]));
			super.addField(Request.RequestUrl, c[1], line.indexOf(c[1]));
			super.addField(Request.RequestVersion, c[2], line.indexOf(c[2]));
		}
	}

	/**
	 * Field value.
	 * 
	 * @param field
	 *          the field
	 * @return the string
	 */
	public String fieldValue(Request field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * Field value.
	 * 
	 * @param field
	 *          the field
	 * @return the string
	 */
	public String fieldValue(Response field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * Checks for content.
	 * 
	 * @return true, if successful
	 */
	public boolean hasContent() {
		return hasField(Response.Content_Type) || hasField(Request.Content_Type);
	}

	/**
	 * Checks for content type.
	 * 
	 * @return true, if successful
	 */
	public boolean hasContentType() {
		return hasField(Response.Content_Type);
	}

	/**
	 * Checks for field.
	 * 
	 * @param field
	 *          the field
	 * @return true, if successful
	 */
	public boolean hasField(Request field) {
		return super.hasField(field);
	}

	/**
	 * Checks for field.
	 * 
	 * @param field
	 *          the field
	 * @return true, if successful
	 */
	public boolean hasField(Response field) {
		return super.hasField(field);
	}

	/**
	 * Checks if is response.
	 * 
	 * @return true, if is response
	 */
	public boolean isResponse() {
		return getMessageType() == MessageType.RESPONSE;
	}

	/**
	 * Gets the raw header instead of reconstructing it.
	 * 
	 * @return original raw header
	 */
	public String header() {
		return super.rawHeader;
	}
}
