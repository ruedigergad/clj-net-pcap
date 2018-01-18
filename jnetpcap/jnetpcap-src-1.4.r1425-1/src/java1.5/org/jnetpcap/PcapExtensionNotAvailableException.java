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
 * Exception is thrown when a pcap extension is accessed, one of its methods,
 * while it is not supported on this particular platform. You must use
 * appropriate <code>isSupported</code> method call that is available with the
 * extension (i.e. <code>WinPcap.isSupported()</code>).
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapExtensionNotAvailableException
    extends IllegalStateException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 4206020497547882412L;

	/**
	 * Instantiates a new pcap extension not available exception.
	 */
  public PcapExtensionNotAvailableException() {
	  super();
	  // TODO Auto-generated constructor stub
  }

	/**
	 * Instantiates a new pcap extension not available exception.
	 * 
	 * @param message
	 *          the message
	 * @param cause
	 *          the cause
	 */
  public PcapExtensionNotAvailableException(String message, Throwable cause) {
	  super(message, cause);
	  // TODO Auto-generated constructor stub
  }

	/**
	 * Instantiates a new pcap extension not available exception.
	 * 
	 * @param s
	 *          the s
	 */
  public PcapExtensionNotAvailableException(String s) {
	  super(s);
	  // TODO Auto-generated constructor stub
  }

	/**
	 * Instantiates a new pcap extension not available exception.
	 * 
	 * @param cause
	 *          the cause
	 */
  public PcapExtensionNotAvailableException(Throwable cause) {
	  super(cause);
	  // TODO Auto-generated constructor stub
  }

}
