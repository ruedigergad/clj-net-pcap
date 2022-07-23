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
package org.jnetpcap;

// TODO: Auto-generated Javadoc
/**
 * Thrown if Pcap object is access after it has been closed.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapClosedException
    extends IllegalStateException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 4803545074835523202L;

	/**
	 * Instantiates a new pcap closed exception.
	 */
	public PcapClosedException() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * Instantiates a new pcap closed exception.
	 * 
	 * @param message
	 *          the message
	 * @param cause
	 *          the cause
	 */
	public PcapClosedException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Instantiates a new pcap closed exception.
	 * 
	 * @param s
	 *          the s
	 */
	public PcapClosedException(String s) {
		super(s);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Instantiates a new pcap closed exception.
	 * 
	 * @param cause
	 *          the cause
	 */
	public PcapClosedException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

}
