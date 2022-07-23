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
package org.jnetpcap.packet.structure;

// TODO: Auto-generated Javadoc
/**
 * The Class HeaderDefinitionError.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class HeaderDefinitionError
    extends RuntimeException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -1034165417637411714L;

	/** The c. */
	private final Class<?> c;

	/**
	 * Instantiates a new header definition error.
	 * 
	 * @param c
	 *          the c
	 */
	public HeaderDefinitionError(Class<?> c) {
		super();
		this.c = c;
	}

	/**
	 * Instantiates a new header definition error.
	 * 
	 * @param message
	 *          the message
	 */
	public HeaderDefinitionError(String message) {
		super(message);
		this.c = null;
	}

	/**
	 * Instantiates a new header definition error.
	 * 
	 * @param c
	 *          the c
	 * @param message
	 *          the message
	 */
	public HeaderDefinitionError(Class<?> c, String message) {
		super(message);
		this.c = c;
	}

	/**
	 * Instantiates a new header definition error.
	 * 
	 * @param cause
	 *          the cause
	 */
	public HeaderDefinitionError(Throwable cause) {
		super(cause);
		this.c = null;

	}

	/**
	 * Instantiates a new header definition error.
	 * 
	 * @param c
	 *          the c
	 * @param cause
	 *          the cause
	 */
	public HeaderDefinitionError(Class<?> c, Throwable cause) {
		super(cause);
		this.c = c;

	}

	/**
	 * Instantiates a new header definition error.
	 * 
	 * @param message
	 *          the message
	 * @param cause
	 *          the cause
	 */
	public HeaderDefinitionError(String message, Throwable cause) {
		super(message, cause);

		this.c = null;
	}

	/**
	 * Instantiates a new header definition error.
	 * 
	 * @param c
	 *          the c
	 * @param message
	 *          the message
	 * @param cause
	 *          the cause
	 */
	public HeaderDefinitionError(Class<?> c, String message, Throwable cause) {
		super(message, cause);
		this.c = c;
	}

	/**
	 * Gets the header.
	 * 
	 * @return the header
	 */
	public Class<?> getHeader() {
		return c;
	}

	/**
	 * Gets the message.
	 * 
	 * @return the message
	 * @see java.lang.Throwable#getMessage()
	 */
	@Override
	public String getMessage() {
		if (c != null) {

			return "[" + getPath() + "] " + super.getMessage();
		} else {
			return super.getMessage();
		}
	}
	
	/**
	 * Gets the path.
	 * 
	 * @return the path
	 */
	protected String getPath() {
		String ci = "";
		for (Class<?> p = c; p != null; p = p.getEnclosingClass()) {

			ci = p.getSimpleName() + "." + ci;
		}
		
		return ci;
	}

}
