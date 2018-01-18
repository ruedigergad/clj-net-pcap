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
package org.jnetpcap.packet.format;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.JPacket;

// TODO: Auto-generated Javadoc
/**
 * Various static formatting utilities.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class FormatUtils {

	/** The Constant DAY_MILLIS. */
	private final static int DAY_MILLIS = 24 * 60 * 60 * 1000;

	/** The Constant HOUR_MILLIS. */
	private final static int HOUR_MILLIS = 60 * 60 * 1000;

	/** The Constant MINUTE_MILLIS. */
	private final static int MINUTE_MILLIS = 60 * 1000;

	/** The Constant multiLineStringList. */
	private final static List<String> multiLineStringList =
			new ArrayList<String>();

	/*
	 * Few constants to help with breakdown of millis to various larger units of
	 * time
	 */
	/** The Constant SECOND_MILLIS. */
	private final static int SECOND_MILLIS = 1000;

	/** The SPAC e_ char. */
	private static String SPACE_CHAR = " ";

	/** The table. */
	static String[] table = new String[256];

	/** The Constant WEEK_MILLIS. */
	private final static int WEEK_MILLIS = 7 * 24 * 60 * 60 * 1000;

	static {
		initTable1char();
	}

	/**
	 * Inits the table1char.
	 */
	private static void initTable1char() {
		for (int i = 0; i < 31; i++) {
			table[i] = ".";
		}

		for (int i = 31; i < 127; i++)
			table[i] = new String(new byte[] {
				(byte) i
			});

		for (int i = 127; i < 256; i++) {
			table[i] = ".";
		}
	}

	/**
	 * Inits the table3chars.
	 */
	@SuppressWarnings("unused")
	private static void initTable3chars() {
		for (int i = 0; i < 31; i++) {
			table[i] = "\\" + Integer.toHexString(i);
			if (table[i].length() == 2)
				table[i] += " ";
		}

		for (int i = 31; i < 127; i++)
			table[i] = new String(new byte[] {
					(byte) i, ' ', ' '
			});

		for (int i = 127; i < 256; i++) {
			table[i] = "\\" + Integer.toHexString(i);
			if (table[i].length() == 2)
				table[i] += " ";
		}

		table[0] = "\\0 ";
		table[7] = "\\a ";
		table[11] = "\\v ";
		table['\b'] = "\\b ";
		table['\t'] = "\\t ";
		table['\n'] = "\\n ";
		table['\f'] = "\\f ";
		table['\r'] = "\\r ";

	}

	/**
	 * Converts the given byte array to a string using a default separator
	 * character.
	 * 
	 * @param array
	 *            array to convert
	 * @return the converted string
	 */
	public static String asString(byte[] array) {
		return asString(array, ':');
	}

	/**
	 * Convers the given byte array to a string using the supplied separator
	 * character.
	 * 
	 * @param array
	 *            array to convert
	 * @param separator
	 *            separator character to use in between array elements
	 * @return the converted string
	 */
	public static String asString(byte[] array, char separator) {
		return asString(array, separator, 16); // Default HEX
	}

	/**
	 * Converts the given byte array to a string using the supplied separator
	 * character and radix for conversion of the numerical component.
	 * 
	 * @param array
	 *            array to convert
	 * @param separator
	 *            separator character to use in between array elements
	 * @param radix
	 *            numerical radix to use for numbers
	 * @return the converted string
	 */
	public static String asString(byte[] array, char separator, int radix) {
		return asString(array, separator, radix, 0, array.length);
	}

	/**
	 * Convers the given byte array to a string using the supplied separator
	 * character.
	 * 
	 * @param array
	 *            array to convert
	 * @param separator
	 *            separator character to use in between array elements
	 * @param radix
	 *            the radix
	 * @param start
	 *            the start
	 * @param len
	 *            the len
	 * @return the converted string
	 */
	public static String asString(byte[] array, char separator, int radix,
			int start, int len) {

		final StringBuilder buf = new StringBuilder();

		for (int i = start; i < (start + len); i++) {
			byte b = array[i];
			if (buf.length() != 0) {
				buf.append(separator);
			}

			buf.append(Integer.toString((b < 0) ? b + 256 : b, radix)
					.toUpperCase());
		}

		return buf.toString();
	}

	/**
	 * Convers the given byte array to a string using the supplied separator
	 * character.
	 * 
	 * @param array
	 *            array to convert
	 * @param separator
	 *            separator character to use in between array elements
	 * @param radix
	 *            the radix
	 * @param start
	 *            the start
	 * @param len
	 *            the len
	 * @return the converted string
	 */
	public static String asStringZeroPad(byte[] array, char separator,
			int radix, int start, int len) {

		final StringBuilder buf = new StringBuilder();

		for (int i = start; i < (start + len); i++) {
			byte b = array[i];
			if (buf.length() != 0) {
				buf.append(separator);
			}

			final String s =
					Integer.toString((b < 0) ? b + 256 : b, radix)
							.toUpperCase();

			if (s.length() == 1) {
				buf.append('0');
			}

			buf.append(s);
		}

		return buf.toString();
	}

	/**
	 * Ip.
	 * 
	 * @param address
	 *            the address
	 * @return the string
	 */
	public static String ip(byte[] address) {
		if (address.length == 4) {
			return asString(address, '.', 10);
		} else {
			return asStringIp6(address, true);
		}
	}

	/**
	 * Mac.
	 * 
	 * @param address
	 *            the address
	 * @return the string
	 */
	public static String mac(byte[] address) {
		return asStringZeroPad(address, ':', 16, 0, address.length);
	}

	/**
	 * Handles various forms of ip6 addressing
	 * 
	 * <pre>
	 * 2001:0db8:0000:0000:0000:0000:1428:57ab
	 * 2001:0db8:0000:0000:0000::1428:57ab
	 * 2001:0db8:0:0:0:0:1428:57ab
	 * 2001:0db8:0:0::1428:57ab
	 * 2001:0db8::1428:57ab
	 * 2001:db8::1428:57ab
	 * </pre>
	 * 
	 * .
	 * 
	 * @param array
	 *            address array
	 * @param holes
	 *            if true holes are allowed
	 * @return formatted string
	 */
	public static String asStringIp6(byte[] array, boolean holes) {

		if (array.length != 16) {
			throw new IllegalArgumentException(
					"expecting 16 byte ip6 address array");
		}

		StringBuilder buf = new StringBuilder();

		int len = 0;
		int start = -1;
		/*
		 * Check for byte compression where sequential zeros are replaced with
		 * ::
		 */
		/*
		 * Bug Fix#117 - FormatUtils.asStringIp6() causes an
		 * OutOfMemoryException
		 */
		for (int i = 0; i < array.length && holes; i++) {
			if ((i % 2) == 0 && array[i] == 0 && array[i + 1] == 0) {
				if (len == 0) {
					start = i;
				}
			}
			i++;
			len += 2;

			/*
			 * Only the first sequence of 0s is compressed, so break out
			 */
			if (array[i] != 0 && len != 0) {
				break;
			}
		}

		/*
		 * Now round off to even length so that only pairs are compressed
		 */
		if (start != -1 && (start % 2) == 1) {
			start++;
			len--;
		}

		if (start != -1 && (len % 2) == 1) {
			len--;
		}

		for (int i = 0; i < array.length; i++) {
			if (i == start) {
				buf.append(':');
				i += len - 1;

				if (i == array.length - 1) {
					buf.append(':');
				}
				continue;
			}

			byte b = array[i];

			if (buf.length() != 0 && (i % 2) == 0) {
				buf.append(':');
			}
			
			/*
			 * Bug fix#125 FormatUtils.asStringIp6 prepends byte values < 0 with zeros 
			 */
			if (b >=0 && b < 16) {
				buf.append('0');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}

		return buf.toString();
	}

	/**
	 * Formats a delta time.
	 * 
	 * @param millis
	 *            delta timestamp in millis
	 * @return formatted string
	 */
	public static String formatTimeInMillis(long millis) {

		StringBuilder b = new StringBuilder();

		long u = 0;

		while (millis > 0) {
			if (b.length() != 0) {
				b.append(' ');
			}

			if (millis > WEEK_MILLIS) {
				u = millis / WEEK_MILLIS;
				b.append(u).append(' ').append((u > 1) ? "weeks" : "week");
				millis -= u * WEEK_MILLIS;

			} else if (millis > DAY_MILLIS) {
				u = millis / DAY_MILLIS;
				b.append(u).append(' ').append((u > 1) ? "days" : "day");
				millis -= u * DAY_MILLIS;

			} else if (millis > HOUR_MILLIS) {
				u = millis / HOUR_MILLIS;
				b.append(u).append(' ').append((u > 1) ? "days" : "day");
				millis -= u * HOUR_MILLIS;

			} else if (millis > MINUTE_MILLIS) {
				u = millis / MINUTE_MILLIS;
				b.append(u).append(' ').append((u > 1) ? "minutes" : "minute");
				millis -= u * MINUTE_MILLIS;

			} else if (millis > SECOND_MILLIS) {
				u = millis / SECOND_MILLIS;
				b.append(u).append(' ').append((u > 1) ? "seconds" : "second");
				millis -= u * SECOND_MILLIS;

			} else if (millis > 0) {
				u = millis;
				b.append(u).append(' ').append((u > 1) ? "millis" : "milli");
				millis -= u;
			}
		}

		return b.toString();
	}

	/**
	 * Formats a byte array to a hexdump string.
	 * 
	 * @param array
	 *            array to convert
	 * @param addressOffset
	 *            offset of the address space reported
	 * @param dataOffset
	 *            offset of the data space reported
	 * @param doAddress
	 *            flag which specifies if address should be printed
	 * @param doText
	 *            flag which specifies if text should printed
	 * @param doData
	 *            flag which specifies if data should printed
	 * @return converted string array, one array element per line of output
	 */
	public static String[] hexdump(byte[] array, int addressOffset,
			int dataOffset, boolean doAddress, boolean doText, boolean doData) {

		return hexdump(array,
				addressOffset,
				dataOffset,
				doAddress,
				doText,
				doData,
				null);
	}

	/**
	 * Markers.
	 * 
	 * @param state
	 *            the state
	 * @return the int[][]
	 */
	public static int[][] markers(JPacket.State state) {
		int[][] markers = new int[state.getHeaderCount() + 1][2];
		markers[0][0] = -1;
		markers[0][1] = -1;

		for (int i = 0; i < state.getHeaderCount(); i++) {
			markers[i + 1][0] = state.getHeaderOffsetByIndex(i);
			markers[i + 1][1] = state.getHeaderLengthByIndex(i);
		}

		return markers;
	}

	/**
	 * Formats a byte array to a hexdump string.
	 * 
	 * @param array
	 *            array to convert
	 * @param addressOffset
	 *            offset of the address space reported
	 * @param dataOffset
	 *            offset of the data space reported
	 * @param doAddress
	 *            flag which specifies if address should be printed
	 * @param doText
	 *            flag which specifies if text should printed
	 * @param doData
	 *            flag which specifies if data should printed
	 * @param markers
	 *            the markers
	 * @return converted string array, one array element per line of output
	 */
	public static String[] hexdump(byte[] array, int addressOffset,
			int dataOffset, boolean doAddress, boolean doText, boolean doData,
			int[][] markers) {

		multiLineStringList.clear();

		for (int i = 0; i + dataOffset < array.length; i += 16) {
			multiLineStringList.add(hexLine(array, i + addressOffset, i
					+ dataOffset, doAddress, doText, doData, markers));
		}

		return multiLineStringList.toArray(new String[multiLineStringList
				.size()]);
	}

	/**
	 * Formats the supplied array for single line combined hexdump output using
	 * all possible options turned on.
	 * 
	 * @param array
	 *            source array
	 * @return a multi-line string containing verbose hexdump
	 */
	public static String hexdump(byte[] array) {
		return hexdumpCombined(array, 0, 0, true, true, true);
	}

	/**
	 * Formats the supplied packet for single line combined hexdump output using
	 * all possible options turned on. Also displays markers which mark
	 * boundaries between each header.
	 * 
	 * @param packet
	 *            source of data
	 * @return a multi-line string containing verbose hexdump
	 */
	public static String hexdump(JPacket packet) {
		return hexdump(packet.getByteArray(0, packet.size()), packet.getState());
	}

	/**
	 * Formats the supplied array for single line combined hexdump output using
	 * all possible options turned on.
	 * 
	 * @param array
	 *            source array
	 * @param state
	 *            the state
	 * @return a multi-line string containing verbose hexdump
	 */
	public static String hexdump(byte[] array, JPacket.State state) {
		return hexdumpCombined(array, 0, 0, true, true, true, markers(state));
	}

	/**
	 * Converts the byte arra to hexdump string.
	 * 
	 * @param array
	 *            array to convert
	 * @param addressOffset
	 *            offset of the address space reported
	 * @param dataOffset
	 *            offset of the data space reported
	 * @param doAddress
	 *            flag which specifies if address should be printed
	 * @param doText
	 *            flag which specifies if text should printed
	 * @param doData
	 *            flag which specifies if data should printed
	 * @return converted string
	 */
	public static String hexdumpCombined(byte[] array, int addressOffset,
			int dataOffset, boolean doAddress, boolean doText, boolean doData) {

		return hexdumpCombined(array,
				addressOffset,
				dataOffset,
				doAddress,
				doText,
				doData,
				null);
	}

	/**
	 * Converts the byte arra to hexdump string.
	 * 
	 * @param array
	 *            array to convert
	 * @param addressOffset
	 *            offset of the address space reported
	 * @param dataOffset
	 *            offset of the data space reported
	 * @param doAddress
	 *            flag which specifies if address should be printed
	 * @param doText
	 *            flag which specifies if text should printed
	 * @param doData
	 *            flag which specifies if data should printed
	 * @param markers
	 *            the markers
	 * @return converted string
	 */
	public static String hexdumpCombined(byte[] array, int addressOffset,
			int dataOffset, boolean doAddress, boolean doText, boolean doData,
			int[][] markers) {
		StringBuilder b = new StringBuilder();
		for (String s : hexdump(array,
				addressOffset,
				dataOffset,
				doAddress,
				doText,
				doData,
				markers)) {
			b.append(s).append('\n');
		}

		return b.toString();
	}

	/**
	 * Converts the byte arra to hexdump string.
	 * 
	 * @param array
	 *            array to convert
	 * @param addressOffset
	 *            offset of the address space reported
	 * @param dataOffset
	 *            offset of the data space reported
	 * @param doAddress
	 *            flag which specifies if address should be printed
	 * @param doText
	 *            flag which specifies if text should printed
	 * @param doData
	 *            flag which specifies if data should printed
	 * @param markers
	 *            the markers
	 * @return converted string array, one array element per line of output
	 */
	public static String hexLine(byte[] array, int addressOffset,
			int dataOffset, boolean doAddress, boolean doText, boolean doData,
			int[][] markers) {

		String s = "";

		if (doAddress) {
			s += hexLineAddress(addressOffset);
			s += ":";
		}

		if (doData) {
			s += hexLineData(array, dataOffset, markers);
		}

		if (doText) {
			s += SPACE_CHAR;
			s += SPACE_CHAR;
			s += SPACE_CHAR;

			s += hexLineText(array, dataOffset);
		}

		return (s);
	}

	/**
	 * Format an address.
	 * 
	 * @param address
	 *            integer address
	 * @return formatted address string
	 */
	public static String hexLineAddress(int address) {
		String s = "";

		s = Integer.toHexString(address);

		for (int i = s.length(); i < 4; i++)
			s = "0" + s;

		return (s);
	}

	/**
	 * Formats the data array as a hexdump.
	 * 
	 * @param data
	 *            data array
	 * @param offset
	 *            offset into the array
	 * @return formatted string
	 */
	public static String hexLineData(byte[] data, int offset) {
		String s = "";

		int i = 0;
		for (i = 0; i + offset < data.length && i < 16; i++) {
			final int o = i + offset;
			if (i == 0) {
				s += SPACE_CHAR;
			}

			/**
			 * Insert a space every 4 characaters.
			 */
			if (i % 4 == 0 && i != 0) {
				s += SPACE_CHAR;
			}

			s += toHexString(data[o]) + SPACE_CHAR;

		}

		/**
		 * Continue the loop and append spaces to fill in the missing data.
		 */
		for (; i < 16; i++) {
			/**
			 * Insert a space every 4 characaters.
			 */
			if (i % 4 == 0 && i != 0)
				s += SPACE_CHAR;

			s += SPACE_CHAR + SPACE_CHAR + SPACE_CHAR;
		}

		return (s);
	}

	/**
	 * Formats the data array as a hexdump.
	 * 
	 * @param data
	 *            data array
	 * @param offset
	 *            offset into the array
	 * @return formatted string
	 */
	public static String hexLineStream(byte[] data, int offset) {
		String s = "";

		int i = 0;
		for (i = 0; i + offset < data.length; i++) {
			final int o = i + offset;

			s += toHexString(data[o]);

		}

		return (s);
	}

	/**
	 * Formats the data array as a hexdump.
	 * 
	 * @param data
	 *            data array
	 * @param offset
	 *            offset into the array
	 * @param markers
	 *            the markers
	 * @return formatted string
	 */
	public static String hexLineData(byte[] data, int offset, int[][] markers) {

		if (markers == null) {
			return hexLineData(data, offset);
		}

		final StringBuilder b = new StringBuilder();

		final String m[] = {
				"*", "*"
		};

		int marker = findMarker(markers, offset);
		int start = markers[marker][0];
		int end = start + markers[marker][1] - 1;

		int i = 0;
		for (i = 0; i + offset < data.length && i < 16; i++) {
			final int o = i + offset;
			if (o == 0 && o == start) {
				b.append(m[marker % 2]);
			} else if (i == 0) {
				b.append(SPACE_CHAR);
			}

			/**
			 * Insert a space every 4 characaters.
			 */
			if (i % 4 == 0 && i != 0)
				b.append(SPACE_CHAR);

			if (o == end) {
				marker = findMarker(markers, o + 1);
				start = markers[marker][0];
				end = start + markers[marker][1] - 1;

				b.append(toHexString(data[o])).append(m[marker % 2]);

			} else {
				b.append(toHexString(data[o])).append(SPACE_CHAR);

			}
		}

		/**
		 * Continue the loop and append spaces to fill in the missing data.
		 */
		for (; i < 16; i++) {
			/**
			 * Insert a space every 4 characaters.
			 */
			if (i % 4 == 0 && i != 0)
				b.append(SPACE_CHAR);

			b.append(SPACE_CHAR).append(SPACE_CHAR).append(SPACE_CHAR);
		}

		return b.toString();
	}

	/**
	 * Find marker.
	 * 
	 * @param markers
	 *            the markers
	 * @param offset
	 *            the offset
	 * @return the int
	 */
	private static int findMarker(int[][] markers, int offset) {
		for (int i = 0; i < markers.length; i++) {
			final int start = markers[i][0];
			final int end = start + markers[i][1] - 1;
			if (offset >= start && offset < end) {
				return i;
			}

		}

		return 0;
	}

	/**
	 * Formats the array data to human readable text that appears at the end of
	 * a hexline of a hexdump.
	 * 
	 * @param data
	 *            data array
	 * @param offset
	 *            offset into data array
	 * @return formatted string
	 */
	public static String hexLineText(byte[] data, int offset) {

		String s = "";

		int i;
		for (i = 0; i + offset < data.length && i < 16; i++) {
			s += table[data[i + offset] & 0xFF];

			// if(Character.isLetterOrDigit(table[data[i + offset] & 0xFF]) ||
			// (table[data[i + offset] & 0xFF]) == ' ')
			// s += " " + table[data[i + offset] & 0xFF];
			// else
			// s += " " + NONPRINTABLE_CHAR;
		}

		/**
		 * Continue the loop and fill in any missing data less than 16 bytes.
		 */
		for (; i < 16; i++) {
			s += SPACE_CHAR;
		}

		return (s);
	}

	/**
	 * Parses a string containing hex numbers to a byte array.
	 * 
	 * @param source
	 *            source string
	 * @return byte array from the parsed data
	 */
	public static byte[] toByteArray(String source) {

		String s = source.replaceAll(" |\n", "");

		byte[] b = new byte[s.length() / 2];

		if ((s.length() % 2) != 0) {
			System.err.println(s);
			throw new IllegalArgumentException(
					"need even number of hex double digits [" + s.length()
							+ "]");
		}

		for (int i = 0; i < s.length(); i += 2) {
			String q = s.substring(i, i + 2);
			// System.out.print(q);
			b[i / 2] = (byte) Integer.parseInt(q, 16);
		}

		return b;
	}

	/**
	 * Formats a number to hext.
	 * 
	 * @param b
	 *            input byte
	 * @return formatted string
	 */
	public static String toHexString(byte b) {
		String s = Integer.toHexString((b) & 0xFF);

		if (s.length() == 1)
			return ("0" + s);

		return (s);
	}
}
