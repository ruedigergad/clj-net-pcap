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

import java.util.logging.Formatter;
import java.util.logging.LogRecord;

// TODO: Auto-generated Javadoc
/**
 * The Class JNetPcapFormatter.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JNetPcapFormatter
    extends Formatter {

	/**
	 * Instantiates a new j net pcap formatter.
	 */
	public JNetPcapFormatter() {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.util.logging.Formatter#format(java.util.logging.LogRecord)
	 */
	/**
	 * Format.
	 * 
	 * @param record
	 *          the record
	 * @return the string
	 * @see java.util.logging.Formatter#format(java.util.logging.LogRecord)
	 */
	@Override
	public String format(LogRecord record) {
		final String msg =
		    String.format(record.getMessage(), record.getParameters());
		record.getLoggerName().split("\\.");
		String prefix = prefix(record);

		Throwable thrown = record.getThrown();
		String error = "";
		if (thrown != null) {
			StringBuilder b = new StringBuilder();
			String ex = thrown.getClass().getCanonicalName() + ":";
//			b.append(prefix).append(" ");
			b.append(ex).append(" ");
			b.append(thrown.getMessage()).append("\n");
			
			for (StackTraceElement e : thrown.getStackTrace()) {
				b.append(ex).append(" ");
				b.append(e.toString()).append("\n");
			}

			error = b.toString();
		}

		return String.format(prefix + " %s\n%s", msg, error);
	}

	/**
	 * Prefix.
	 * 
	 * @param record
	 *          the record
	 * @return the string
	 */
	private String prefix(LogRecord record) {
		String[] c = record.getLoggerName().split("\\.");

		return String.format("%s:%s:", record.getLevel().toString(),
		    c[c.length - 1], record.getSourceMethodName());
	}
}
