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
package org.jnetpcap.util;

import java.util.LinkedList;
import java.util.List;

// TODO: Auto-generated Javadoc
/**
 * A special string that allows easy expandibility within it. The
 * ExpandableString is made up of 2 parts. A template string and a work buffer.
 * Whenever a reset() call is made, the buffer is replaced with the contents of
 * the template. The various replace calls, change the buffer by replacing
 * certain parts, recursively. Subclasses perform specific expand operations,
 * that are suited for their needs. Substitutions between single quotes are
 * omitted and returned untouched. Everything else that is not single quoted,
 * can be expanded. Escape character, the back-slash, is treated with a lot of
 * respect.
 * <p>
 * For example ConfigString subclass replaces variables and properties (marked
 * with $ and &#64; signs respectively) with contents from various maps and
 * properties.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class ExpandableString
    extends JStringBuilder {

	/** The count. */
	protected int count = 0;

	/** The end. */
	protected int end;

	/** The quoted. */
	private final List<String> quoted = new LinkedList<String>();

	/** The start. */
	protected int start;

	/** The template. */
	private String template;

	/**
	 * Instantiates a new expandable string.
	 * 
	 * @param template
	 *          the template
	 */
	public ExpandableString(String template) {
		this.template = template;
		super.append(template);
	}

	/**
	 * Gets the template.
	 * 
	 * @return the template
	 */
	public final String getTemplate() {
		return this.template;
	}

	/**
	 * Removes the.
	 * 
	 * @param seq
	 *          the seq
	 * @return true, if successful
	 */
	public boolean remove(String seq) {
		return replaceSequence(seq, "", "");
	}

	/**
	 * Replace sequence.
	 * 
	 * @param open
	 *          the open
	 * @param close
	 *          the close
	 * @param with
	 *          the with
	 * @return true, if successful
	 */
	public boolean replaceSequence(String open, String close, String with) {
		while (scanNext(open, close) && start != -1) {
			super.replace(start, end + 1, with);
		}

		return (start == -1) ? true : false;
	}

	/**
	 * Reset.
	 * 
	 * @return the expandable string
	 */
	public ExpandableString reset() {
		super.setLength(0);
		super.append(template);
		this.start = 0;
		this.end = 0;

		return this;
	}

	/**
	 * Restore quotes.
	 * 
	 * @return true, if successful
	 */
	protected boolean restoreQuotes() {
		while (scanNext("\\\\'", "\\\\'") && start != -1) {
			super.replace(start, end + 3, quoted.remove(0));
		}

		return (start == -1) ? true : false;
	}

	/**
	 * Save quotes.
	 * 
	 * @return true, if successful
	 */
	protected boolean saveQuotes() {
		quoted.clear();

		while (scanNext("'", "'") && start != -1) {

			quoted.add(super.substring(start, end + 1));

			super.replace(start, end + 1, "\\\\'\\\\'"); // Twice escaped empty quote
		}

		return (start == -1) ? true : false;
	}

	/**
	 * Scan next.
	 * 
	 * @param open
	 *          the open
	 * @param close
	 *          the close
	 * @return true, if successful
	 */
	protected boolean scanNext(String open, String close) {
		return scanNext(open, close, 0);
	}

	/**
	 * Scan next.
	 * 
	 * @param open
	 *          the open
	 * @param close
	 *          the close
	 * @param offset
	 *          the offset
	 * @return true, if successful
	 */
	protected boolean scanNext(String open, String close, int offset) {

		start = super.indexOf(open, offset);
		if (start == -1) {
			return true; // NORMAL EXIT HERE - We're done
		}

		/*
		 * Check for escaped characters
		 */
		if (start != 0 && super.charAt(start - 1) == '\\') {
			return scanNext(open, close, start + 1); // Resume scan just passed it
		}

		if (scanNextEnd(close, start + 1) == false) {
			return false;
		}

		count++;

		return true;
	}

	/**
	 * Scan next end.
	 * 
	 * @param close
	 *          the close
	 * @param offset
	 *          the offset
	 * @return true, if successful
	 */
	private boolean scanNextEnd(String close, int offset) {
		end = super.indexOf(close, offset);
		if (end == -1) {
			return false; // Missing matching close
		}

		if (end != 0 && super.charAt(end - 1) == '\\') {
			return scanNextEnd(close, end + 1);
		}

		return true;
	}

	/**
	 * Sets the template.
	 * 
	 * @param template
	 *          the template to set
	 */
	public final void setTemplate(String template) {
		this.template = template;
		reset();
	}

	/**
	 * Template.
	 * 
	 * @return the string
	 */
	public String template() {
		return this.template;
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see org.jnetpcap.util.JStringBuilder#toString()
	 */
	public String toString() {
		return super.toString();
	}
}
