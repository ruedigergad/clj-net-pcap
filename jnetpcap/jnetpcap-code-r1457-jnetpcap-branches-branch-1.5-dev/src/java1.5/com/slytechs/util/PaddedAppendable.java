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
package com.slytechs.util;

import java.io.IOException;
import java.util.Stack;

// TODO: Auto-generated Javadoc
/**
 * The Class PaddedAppendable.
 */

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * 
 */
public class PaddedAppendable implements Appendable {

	/** The indent. */
	private final Stack<String> indent = new Stack<String>();

	/** The new line. */
	private boolean newLine;

	/** The out. */
	private final Appendable out;

	/**
	 * Instantiates a new padded appendable.
	 */
	public PaddedAppendable() {
		this(System.out);
	}

	/**
	 * Instantiates a new padded appendable.
	 * 
	 * @param out
	 *          the out
	 */
	public PaddedAppendable(Appendable out) {
		this.out = out;
		this.newLine = true;
	}

	/**
	 * A.
	 * 
	 * @param c
	 *          the c
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable a(char c) throws IOException {
		out.append(c);

		return this;
	}

	/**
	 * A.
	 * 
	 * @param csq
	 *          the csq
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable a(CharSequence... csq) throws IOException {

		if (newLine) {
			pad();
		}

		for (CharSequence s : csq) {
			out.append(s);
		}

		return this;
	}

	/**
	 * A.
	 * 
	 * @param csq
	 *          the csq
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable a(CharSequence csq, int start, int end)
			throws IOException {
		out.append(csq, start, end);

		return this;
	}

	/**
	 * An.
	 * 
	 * @param csq
	 *          the csq
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable an(CharSequence... csq) throws IOException {
		append(csq);
		nl();

		return this;
	}

	/**
	 * @param c
	 * @return
	 * @throws IOException
	 * @see java.lang.Appendable#append(char)
	 */
	public PaddedAppendable append(char c) throws IOException {
		out.append(c);

		return this;
	}

	/**
	 * Append.
	 * 
	 * @param csq
	 *          the csq
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable append(CharSequence... csq) throws IOException {
		if (newLine) {
			pad();
		}

		for (CharSequence s : csq) {
			out.append(s);
		}

		return this;
	}

	/**
	 * @param csq
	 * @return
	 * @throws IOException
	 * @see java.lang.Appendable#append(java.lang.CharSequence)
	 */
	public PaddedAppendable append(CharSequence csq) throws IOException {
		if (newLine) {
			pad();
		}

		out.append(csq);

		return this;
	}

	/**
	 * @param csq
	 * @param start
	 * @param end
	 * @return
	 * @throws IOException
	 * @see java.lang.Appendable#append(java.lang.CharSequence, int, int)
	 */
	public PaddedAppendable append(CharSequence csq, int start, int end)
			throws IOException {
		out.append(csq, start, end);

		return this;
	}

	/**
	 * Appendln.
	 * 
	 * @param csq
	 *          the csq
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable appendln(CharSequence... csq) throws IOException {
		append(csq);
		nl();

		return this;
	}

	/**
	 * Gets the padding.
	 * 
	 * @return the padding
	 */
	private String getPadding() {
		final String padding = (indent.isEmpty()) ? "" : indent.peek();

		return (padding == null) ? "" : padding;
	}

	/**
	 * New line.
	 * 
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable nl() throws IOException {

		append("\n");
		newLine = true;

		return this;
	}

	/**
	 * New line.
	 * 
	 * @param count
	 *          number of new lines
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable nl(int count) throws IOException {
		while (count-- > 0) {
			nl();
		}

		return this;
	}

	/**
	 * Pad.
	 * 
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable pad() throws IOException {
		out.append(getPadding());
		newLine = false;
		return this;
	}

	/**
	 * Pad.
	 * 
	 * @param str
	 *          the str
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable pad(String str) throws IOException {
		pad();
		append(str);

		return this;
	}

	/**
	 * Padln.
	 * 
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable padln() throws IOException {
		pad();
		nl();

		return this;
	}

	/**
	 * Padln.
	 * 
	 * @param str
	 *          the str
	 * @return the padded appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public PaddedAppendable padln(String str) throws IOException {
		pad();
		append(str);
		nl();

		return this;
	}

	/**
	 * Pop.
	 * 
	 * @return the padded appendable
	 */
	public PaddedAppendable pop() {
		indent.pop();

		return this;
	}

	/**
	 * Push.
	 * 
	 * @return the padded appendable
	 */
	public PaddedAppendable push() {
		return push("");
	}

	/**
	 * Push.
	 * 
	 * @param whitespaceCount
	 *          the whitespace count
	 * @return the padded appendable
	 */
	public PaddedAppendable push(int whitespaceCount) {
		final StringBuilder b = new StringBuilder();

		for (int i = 0; i < whitespaceCount; i++) {
			b.append(' ');
		}

		return push(b.toString());
	}

	/**
	 * Push.
	 * 
	 * @param padding
	 *          the padding
	 * @return the padded appendable
	 */
	public PaddedAppendable push(String padding) {
		indent.push(getPadding() + padding);

		return this;
	}
}
