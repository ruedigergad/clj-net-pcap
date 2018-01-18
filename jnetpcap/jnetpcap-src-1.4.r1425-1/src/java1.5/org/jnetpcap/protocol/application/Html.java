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
package org.jnetpcap.protocol.application;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.util.JThreadLocal;

// TODO: Auto-generated Javadoc
/**
 * Hyper Text Markup Language header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(nicname = "Html", suite = ProtocolSuite.APPLICATION)
public class Html extends JHeader {

	/**
	 * Html tag instance parsed from the html document.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class HtmlTag {

		/**
		 * The Enum Type.
		 */
		public enum Type {

			/** The ATOMIC. */
			ATOMIC,

			/** The CLOSE. */
			CLOSE,

			/** The OPEN. */
			OPEN,
		}

		/** The end. */
		private final int end;

		/** The params. */
		private Map<Tag.Param, String> params = Collections.emptyMap();

		/** The source. */
		private final String source;

		/** The start. */
		private final int start;

		/** The tag. */
		private Tag tag;

		/** The tag string. */
		private final String tagString;

		/** The type. */
		final Type type;

		/**
		 * Instantiates a new html tag.
		 * 
		 * @param tag
		 *            the tag
		 * @param type
		 *            the type
		 * @param tagString
		 *            the tag string
		 * @param source
		 *            the source
		 * @param start
		 *            the start
		 * @param end
		 *            the end
		 */
		public HtmlTag(Tag tag, Type type, String tagString, String source,
				int start, int end) {

			this.tag = tag;
			this.type = type;
			this.tagString = tagString;
			this.source = source;
			this.start = start;
			this.end = end;

			if (type != Type.ATOMIC) {
				parseTag(tag, tagString);
			}

		}

		/**
		 * Gets the end.
		 * 
		 * @return the end
		 */
		public final int getEnd() {
			return this.end;
		}

		/**
		 * Gets the params.
		 * 
		 * @return the params
		 */
		public final Map<Tag.Param, String> getParams() {
			return this.params;
		}

		/**
		 * Gets the source.
		 * 
		 * @return the source
		 */
		public final String getSource() {
			return this.source;
		}

		/**
		 * Gets the start.
		 * 
		 * @return the start
		 */
		public final int getStart() {
			return this.start;
		}

		/**
		 * Gets the tag.
		 * 
		 * @return the tag
		 */
		public final Tag getTag() {
			return this.tag;
		}

		/**
		 * Gets the tag string.
		 * 
		 * @return the tag string
		 */
		public String getTagString() {
			return this.tagString;
		}

		/**
		 * Gets the type.
		 * 
		 * @return the type
		 */
		public final Type getType() {
			return this.type;
		}

		/**
		 * Parses the tag.
		 * 
		 * @param tag
		 *            the tag
		 * @param tagString
		 *            the tag string
		 */
		private void parseTag(Tag tag, String tagString) {
			String[] p = tagString.split(" ");
			
			System.out.printf("html::parseTag=%s%n", tagString);

			if (p.length > 1) {
				this.params = new HashMap<Tag.Param, String>(p.length - 1);
			}

//			for (String s : p) {
//				s = s.trim();
//				String[] c = s.split("=");
//
//				if (c.length == 2) {
//					if (c[1].charAt(0) == '"' || c[1].charAt(0) == '\"') {
//						c[1] = c[1].substring(1, c[1].length() - 2);
//					}
//					Param key = Tag.Param.parseStringPrefix(c[0]);
//					System.out.printf("key=%s, c[1]=%s%n", key, c[1]);
//					if (key != null) {
//						this.params.put(key, c[1]);
//					}
//				}
//			}
		}

		/**
		 * To string.
		 * 
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		public String toString() {
			StringBuilder b = new StringBuilder();

			switch (type) {
			case ATOMIC:
				// b.append(tag.name()).append("<>");
				break;
			case CLOSE:
				b.append(tag.name()).append("/>");
				break;
			case OPEN:
				b.append(tag.name()).append('<');
				break;
			}

			if (tag == Tag.TEXT) {
				// b.append(tag.toString()).append('=');
				b.append('"');
				b.append(parserLocal.get().format(tagString));
				b.append('"');

			} else if (params.isEmpty() == false) {
				b.append('=');
				b.append(params.toString());

			}

			return b.toString();
		}

	}

	/**
	 * Table of supported HTML tags.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Tag {

		/** The A. */
		A,

		/** The B. */
		B,

		/** The BODY. */
		BODY,

		/** The BUTTON. */
		BUTTON,

		/** The CAPTION. */
		CAPTION,

		/** The CENTER. */
		CENTER,

		/** The DIV. */
		DIV,

		/** The EM. */
		EM,

		/** The FORM. */
		FORM,

		/** The H1. */
		H1,

		/** The H2. */
		H2,

		/** The H3. */
		H3,

		/** The H4. */
		H4,

		/** The H5. */
		H5,

		/** The H6. */
		H6,

		/** The HEAD. */
		HEAD,

		/** The HTML. */
		HTML,

		/** The I. */
		I,

		/** The IFRAME. */
		IFRAME,

		/** The IMG. */
		IMG,

		/** The INPUT. */
		INPUT,

		/** The LABEL. */
		LABEL,

		/** The LI. */
		LI,

		/** The LINK. */
		LINK("rel", "type", "href"),

		/** The META. */
		META,

		/** The NOSCRIPT. */
		NOSCRIPT,

		/** The OBJECT. */
		OBJECT,

		/** The OL. */
		OL,

		/** The P. */
		P,

		/** The REL. */
		REL,

		/** The SCRIPT. */
		SCRIPT,

		/** The SPAN. */
		SPAN,

		/** The TABLE. */
		TABLE,

		/** The TBODY. */
		TBODY,

		/** The TD. */
		TD,

		/** The TEXT. */
		TEXT,

		/** The TH. */
		TH,

		/** The TITLE. */
		TITLE,

		/** The TR. */
		TR,

		/** The U. */
		U,

		/** The UL. */
		UL,

		/** The UNKNOWN. */
		UNKNOWN;

		/**
		 * Table of tag parameters.
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum Param {

			/** The ALT. */
			ALT,

			/** The CLASS. */
			CLASS,

			/** The HEIGHT. */
			HEIGHT,

			/** The HREF. */
			HREF,

			/** The ID. */
			ID,

			/** The SRC. */
			SRC,

			/** The TITLE. */
			TITLE,

			/** The TYPE. */
			TYPE,

			/** The UNKNOWN. */
			UNKNOWN,

			/** The WIDTH. */
			WIDTH;

			/**
			 * Parses the string prefix.
			 * 
			 * @param name
			 *            the name
			 * @return the param
			 */
			public static Param parseStringPrefix(String name) {
				for (Param p : values()) {
					if (name.toUpperCase().startsWith(p.name())) {
						return p;
					}
				}

				return UNKNOWN;
			}

		}

		/**
		 * Parses the string prefix.
		 * 
		 * @param name
		 *            the name
		 * @return the tag
		 */
		public static Tag parseStringPrefix(String name) {
			for (Tag t : values()) {
				if (name.toUpperCase().startsWith(t.name())) {
					return t;
				}
			}

			return UNKNOWN;
		}

		/** The params. */
		private final String[] params;

		/**
		 * Instantiates a new tag.
		 * 
		 * @param params
		 *            the params
		 */
		private Tag(String... params) {

			int i = 0;
			for (String p : params) {
				params[i++] = p.trim().toUpperCase();
			}
			this.params = params;

		}

		/**
		 * Gets the params.
		 * 
		 * @return the params
		 */
		public final String[] getParams() {
			return this.params;
		}

	}

	/**
	 * Bind2 http.
	 * 
	 * @param packet
	 *            the packet
	 * @param http
	 *            the http
	 * @return true, if successful
	 */
	@Bind(to = Http.class, stringValue = "text/html")
	public static boolean bind2Http(JPacket packet, Http http) {
		return http.hasContentType()
				&& http.contentType().startsWith("text/html;");
	}

	/**
	 * Bind2 http as css.
	 * 
	 * @param packet
	 *            the packet
	 * @param http
	 *            the http
	 * @return true, if successful
	 */
	@Bind(to = Http.class, stringValue = "text/css")
	public static boolean bind2HttpAsCSS(JPacket packet, Http http) {
		return http.hasContentType()
				&& http.contentType().startsWith("text/css;");
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
	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return buffer.size() - offset;
	}

	/** The page. */
	private String page;

	/** The Constant stringLocal. */
	private static final JThreadLocal<StringBuilder> stringLocal =
			new JThreadLocal<StringBuilder>(StringBuilder.class);

	/** The Constant parserLocal. */
	private static final JThreadLocal<HtmlParser> parserLocal =
			new JThreadLocal<HtmlParser>(HtmlParser.class);

	/** The tags. */
	private HtmlTag[] tags;

	/** The links. */
	private HtmlTag[] links;

	/**
	 * Decode header.
	 * 
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {
		final StringBuilder buf = stringLocal.get();
		buf.setLength(0);

		super.getUTF8String(0, buf, size());

		this.page = buf.toString();

		this.tags = null;
		this.links = null;
	}

	/**
	 * Page.
	 * 
	 * @return the string
	 */
	@Field(offset = 0, format = "#textdump#")
	public String page() {
		return this.page;
	}

	/**
	 * Page length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int pageLength() {
		return size() * 8;
	}

	/**
	 * Tags.
	 * 
	 * @return the html tag[]
	 */
	public HtmlTag[] tags() {
		if (tags == null) {
			tags = parserLocal.get().decodeAllTags(this.page);
		}

		return tags;
	}

	/**
	 * Links.
	 * 
	 * @return the html tag[]
	 */
	public HtmlTag[] links() {
		if (this.links == null) {
			this.links = parserLocal.get().decodeLinks(tags());
		}

		return this.links;
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see org.jnetpcap.packet.JHeader#toString()
	 */
	public String toString() {
		StringBuilder b = new StringBuilder();

		for (HtmlTag t : tags()) {
			b.append(t.toString()).append("\n");
		}

		return b.toString();
	}
}
