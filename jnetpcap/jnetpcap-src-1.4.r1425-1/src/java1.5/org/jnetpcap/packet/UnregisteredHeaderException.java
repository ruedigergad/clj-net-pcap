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
 * Thrown when a lookup on a header in JRegistry fails.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class UnregisteredHeaderException
    extends RegistryRuntimeException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 8734105996858455745L;

	/**
	 * Instantiates a new unregistered header exception.
	 */
	public UnregisteredHeaderException() {
	}

	/**
	 * Instantiates a new unregistered header exception.
	 * 
	 * @param message
	 *          the message
	 */
	public UnregisteredHeaderException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new unregistered header exception.
	 * 
	 * @param cause
	 *          the cause
	 */
	public UnregisteredHeaderException(Throwable cause) {
		super(cause);
	}

	/**
	 * Instantiates a new unregistered header exception.
	 * 
	 * @param message
	 *          the message
	 * @param cause
	 *          the cause
	 */
	public UnregisteredHeaderException(String message, Throwable cause) {
		super(message, cause);
	}

}
