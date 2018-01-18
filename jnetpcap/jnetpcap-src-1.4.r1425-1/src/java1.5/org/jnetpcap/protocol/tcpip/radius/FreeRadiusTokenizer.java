/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011 Sly Technologies, Inc.
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
package org.jnetpcap.protocol.tcpip.radius;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import org.jnetpcap.protocol.tcpip.radius.FreeRadiusTokenizer.Token;

public class FreeRadiusTokenizer implements Iterable<Token>, Iterator<Token> {

	public static class Token {

		@SuppressWarnings("unused")
		private final int lineno;

		public final FreeRadiusTokenizer.TokenType type;

		public final String value;

		public Token(FreeRadiusTokenizer.TokenType type, String value, int lineno) {
			this.type = type;
			this.value = value;
			this.lineno = lineno;
		}

		@Override
		public String toString() {
			if (value != null) {
				return type.name() + "(" + value + ")";

			} else {
				return type.name();
			}
		}

		public String stringValue() {
			return value;
		}

		public int intValue() {
			return Integer.parseInt(value);
		}

		public long longValue() {
			return Long.parseLong(value);
		}

		public double doubleValue() {
			return Double.parseDouble(value);
		}

		public float FloatValue() {
			return Float.parseFloat(value);
		}
	}

	public enum TokenType {
		ASSIGNMENT,

		/**
		 * Attribute
		 */
		ATTRIBUTE,

		BEGIN_VENDOR,

		COMMA,

		ECRYPT,

		END_VENDOR,

		/**
		 * End Of Line
		 */
		EOL,

		/**
		 * End Of Stream
		 */
		EOS,
		/**
		 * format
		 */
		FORMAT,

		HAS_TAG,

		/**
		 * Identifier
		 */
		ID,

		INCLUDE,

		NUMBER,

		VALUE,
		VALUE_TYPE,

		/**
		 * 
		 */
		VENDOR,

	}

	private final BufferedReader in;

	@SuppressWarnings("unused")
	private String line;

	private int lineno = 0;

	private final List<FreeRadiusTokenizer.Token> tokens =
			new LinkedList<FreeRadiusTokenizer.Token>();

	public FreeRadiusTokenizer(BufferedReader in) {
		this.in = in;
	}

	public FreeRadiusTokenizer(InputStream in) {
		this(new BufferedReader(new InputStreamReader(in)));
	}

	public Token consume() throws IOException {
		consume(1);

		return null;
	}

	public Token consume(int count) throws IOException {
		while (count-- > 0) {
			nextToken();
		}

		return null;
	}

	private void fetchTokens() throws IOException {
		String line = in.readLine();
		if (line == null) {
			tokens.add(new Token(TokenType.EOS, null, -1));
			in.close();
			return;
		}

		tokenizeLine(line, lineno++);
	}

	public Token get() throws IOException {
		return nextToken();
	}

	/**
	 * @return
	 * @see java.util.Iterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		try {
			return hasNextToken();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	public boolean hasNextToken() throws IOException {
		return peek().type != TokenType.EOS;
	}

	/**
	 * @return
	 * @see java.lang.Iterable#iterator()
	 */
	@Override
	public Iterator<Token> iterator() {
		return this;
	}

	/**
	 * @return
	 * @see java.util.Iterator#next()
	 */
	@Override
	public Token next() {
		try {
			return nextToken();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	public Token nextToken() throws IOException {
		if (tokens.isEmpty()) {
			fetchTokens();
		}

		FreeRadiusTokenizer.Token token = this.tokens.get(0);
		if (token.type != TokenType.EOS) {
			tokens.remove(0);
		}

		while (token.type == TokenType.EOL && peek(0).type == TokenType.EOL) {
			tokens.remove(0);
		}

		return token;
	}

	public FreeRadiusTokenizer.Token peek() throws IOException {
		return peek(0);
	}

	public FreeRadiusTokenizer.Token peek(int count) throws IOException {
		if (tokens.size() <= count) {
			fetchTokens();
		}

		FreeRadiusTokenizer.Token token = this.tokens.get(count);

		return token;
	}

	public boolean predicate(int offset, TokenType t1) throws IOException {
		return peek(offset + 0).type == t1;
	}

	public boolean predicate(int offset, TokenType t1, TokenType t2)
			throws IOException {
		return peek(offset + 0).type == t1 && peek(offset + 1).type == t2;
	}

	public boolean predicate(int offset, TokenType t1, TokenType t2, TokenType t3)
			throws IOException {
		return peek(offset + 0).type == t1 && peek(offset + 1).type == t2
				&& peek(offset + 2).type == t3;
	}

	public boolean predicate(int offset,
			TokenType t1,
			TokenType t2,
			TokenType t3,
			TokenType t4) throws IOException {
		return peek(offset + 0).type == t1 && peek(offset + 1).type == t2
				&& peek(offset + 2).type == t3 && peek(offset + 3).type == t4;
	}

	public boolean predicate(int offset,
			TokenType t1,
			TokenType t2,
			TokenType t3,
			TokenType t4,
			TokenType... types) throws IOException {
		boolean r =
				peek(offset + 0).type == t1 && peek(offset + 1).type == t2
						&& peek(offset + 2).type == t3 && peek(offset + 3).type == t4;
		if (!r) {
			return false;
		}

		int i = offset + 4;
		for (TokenType t : types) {
			if (peek(i++).type != t) {
				return false;
			}
		}

		return true;
	}

	public Token get(TokenType... types) throws IOException {
		Token token = null;
		for (TokenType t : types) {
			if (token == null && t != null) {
				token = get();
			} else {
				consume();
			}
		}

		return token;
	}

	public Token get(TokenType t1, TokenType t2, TokenType t3, TokenType t4)
			throws IOException {
		Token token = (t1 == null) ? consume() : get();
		token = (token != null || t2 == null) ? consume() : get();
		token = (token != null || t3 == null) ? consume() : get();
		token = (token != null || t4 == null) ? consume() : get();

		return token;
	}

	public boolean predicate(TokenType t1) throws IOException {
		return predicate(0, t1);
	}

	public boolean predicate(TokenType t1, TokenType t2) throws IOException {
		return predicate(0, t1, t2);
	}

	public boolean predicate(TokenType t1, TokenType t2, TokenType t3)
			throws IOException {
		return predicate(0, t1, t2, t3);
	}

	public boolean predicate(TokenType t1,
			TokenType t2,
			TokenType t3,
			TokenType t4) throws IOException {
		return predicate(0, t1, t2, t3, t4);
	}

	public boolean predicate(TokenType t1,
			TokenType t2,
			TokenType t3,
			TokenType t4,
			TokenType... types) throws IOException {
		return predicate(0, t1, t2, t3, t4, types);
	}

	/**
	 * 
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();

	}

	private void tokenizeLine(String line, int lineno) {

		/*
		 * Split on whitespace, comma or =
		 */
		String[] c = line.split("[\\s=,]");

		for (int i = 0; i < c.length; i++) {
			String b = c[i].trim();
			if (b.startsWith("#")) {
				break;
			}

			if (b.equals("VENDOR")) {
				tokens.add(new Token(TokenType.VENDOR, null, lineno));
			} else if (b.equals("format")) {
				tokens.add(new Token(TokenType.FORMAT, null, lineno));
			} else if (b.equals("has_tag")) {
				tokens.add(new Token(TokenType.HAS_TAG, null, lineno));

			} else if (b.equals("ATTRIBUTE")) {
				tokens.add(new Token(TokenType.ATTRIBUTE, null, lineno));
			} else if (b.equals("VALUE")) {
				tokens.add(new Token(TokenType.VALUE, null, lineno));
			} else if (b.equals("$INCLUDE")) {
				tokens.add(new Token(TokenType.INCLUDE, null, lineno));
			} else if (b.equals("BEGIN-VENDOR")) {
				tokens.add(new Token(TokenType.BEGIN_VENDOR, null, lineno));
			} else if (b.equals("END-VENDOR")) {
				tokens.add(new Token(TokenType.END_VENDOR, null, lineno));

			} else if (b.equals("integer")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));
			} else if (b.equals("string")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));
			} else if (b.equals("ipaddr")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));
			} else if (b.equals("ipv6addr")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));
			} else if (b.equals("ipv4prefix")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));
			} else if (b.equals("ifid")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));
			} else if (b.equals("octets")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));
			} else if (b.equals("abinary")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));
			} else if (b.equals("ether")) {
				tokens.add(new Token(TokenType.VALUE_TYPE, b, lineno));

			} else if (Pattern.matches("^0x[0123456789abcdef]+", b)) {
				tokens.add(new Token(TokenType.NUMBER, hex2dec(b), lineno));

			} else if (Pattern.matches("^\\d+", b)) {
				tokens.add(new Token(TokenType.NUMBER, b, lineno));

			} else if (Pattern.matches("^[\\w\\.-]+", b)) {
				tokens.add(new Token(TokenType.ID, b, lineno));
			}
		}

		tokens.add(new Token(TokenType.EOL, null, lineno));
	}

	private String hex2dec(String str) {
		str = str.replaceFirst("0x", "");
		long num = Long.parseLong(str, 16);

		return Long.toString(num);
	}

	@SuppressWarnings("unused")
	private long parseLong(String str, int radix) {
		str = str.replaceFirst("0x", "");
		long num = Long.parseLong(str, 16);

		return num;
	}
}
