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

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.protocol.application.Html.HtmlTag;
import org.jnetpcap.protocol.application.Html.Tag;
import org.jnetpcap.util.JThreadLocal;

// TODO: Auto-generated Javadoc
/**
 * Html header parser.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class HtmlParser {

	/** The e. */
	private int e = 0;

	/** The s. */
	private int s = 0;

	/** The str. */
	private String str = null;

	/** The Constant listLocal. */
	@SuppressWarnings("rawtypes")
	private static final JThreadLocal<ArrayList> listLocal =
	    new JThreadLocal<ArrayList>(ArrayList.class);

	/**
	 * Decode all tags.
	 * 
	 * @param page
	 *          the page
	 * @return the html tag[]
	 */
	@SuppressWarnings("unchecked")
	public HtmlTag[] decodeAllTags(String page) {
		this.e = 0;
		this.s = e;

		final List<HtmlTag> list = listLocal.get();
		list.clear();

		int textStart = 0;
		while (true) {
			final HtmlTag tag = nextTag(page, '<', '>');
			if (tag == null) {
				break;
			}

			if (textStart != this.s) {
				String text = page.substring(textStart, this.s);
				if (text.length() != 0) {
					list.add(new HtmlTag(Tag.TEXT, HtmlTag.Type.ATOMIC, text, page,
					    textStart, this.s));
				}
			}

			textStart = this.e + 1;

			list.add(tag);
		}

		return list.toArray(new HtmlTag[list.size()]);
	}

	/**
	 * Decode links.
	 * 
	 * @param tags
	 *          the tags
	 * @return the html tag[]
	 */
	@SuppressWarnings("unchecked")
	public HtmlTag[] decodeLinks(HtmlTag[] tags) {
		List<HtmlTag> links = listLocal.get();
		links.clear();

		for (HtmlTag t : tags) {
			switch (t.getTag()) {
				case A:
				case LINK:
				case IMG:
				case SCRIPT:
				case FORM:
					if (t.type == HtmlTag.Type.OPEN) {
						links.add(t);
					}
			}
		}

		return links.toArray(new HtmlTag[links.size()]);
	}

	/**
	 * Extract bounded.
	 * 
	 * @param str
	 *          the str
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the string
	 */
	private String extractBounded(String str, char start, char end) {
		if (this.str != str) {
			this.s = 0;
			this.e = 0;
			this.str = str;
		}

		s = str.indexOf('<', e);
		e = str.indexOf('>', s);

		return (s == -1 || e == -1) ? null : str.substring(s + 1, e).trim()
		    .replace("\r\n", "");
	}

	/**
	 * Next tag.
	 * 
	 * @param str
	 *          the str
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the html tag
	 */
	private HtmlTag nextTag(String str, char start, char end) {

		String tagString = extractBounded(str, start, end);
		if (tagString == null) {
			return null;
		}

		Tag tag;
		HtmlTag.Type type = HtmlTag.Type.OPEN;
		if (tagString.charAt(0) == '/') {
			tagString = tagString.substring(1);
			type = HtmlTag.Type.CLOSE;
		}

		tag = Tag.parseStringPrefix(tagString);

		if (tag == null) {
			return null;
		}

		HtmlTag ht = new HtmlTag(tag, type, tagString, this.str, this.s, this.e);

		return ht;
	}

	/**
	 * Format.
	 * 
	 * @param str
	 *          the str
	 * @return the string
	 */
	public String format(String str) {

		str = str.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
		return str;
	}

}
