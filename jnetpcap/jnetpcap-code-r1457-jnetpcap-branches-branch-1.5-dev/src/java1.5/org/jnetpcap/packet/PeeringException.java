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
package org.jnetpcap.packet;

// TODO: Auto-generated Javadoc
/**
 * The Class PeeringException.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PeeringException
    extends Exception {

	/** The Constant serialVersionUID. */
  private static final long serialVersionUID = 7136151191443182266L;

	/**
	 * Instantiates a new peering exception.
	 */
	public PeeringException() {
	}

	/**
	 * Instantiates a new peering exception.
	 * 
	 * @param message
	 *          the message
	 */
	public PeeringException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new peering exception.
	 * 
	 * @param cause
	 *          the cause
	 */
	public PeeringException(Throwable cause) {
		super(cause);
	}

	/**
	 * Instantiates a new peering exception.
	 * 
	 * @param message
	 *          the message
	 * @param cause
	 *          the cause
	 */
	public PeeringException(String message, Throwable cause) {
		super(message, cause);
	}

}
