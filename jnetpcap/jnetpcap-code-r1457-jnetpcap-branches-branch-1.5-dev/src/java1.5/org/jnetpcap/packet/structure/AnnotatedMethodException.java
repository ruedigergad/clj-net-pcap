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
 * The Class AnnotatedMethodException.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedMethodException
    extends HeaderDefinitionError {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1165114276807013103L;

	/** The c. */
	private final Class<?> c;

	/**
	 * Instantiates a new annotated method exception.
	 * 
	 * @param c
	 *          the c
	 */
	public AnnotatedMethodException(Class<?> c) {
		super(c);
		this.c = c;
	}

	/**
	 * Instantiates a new annotated method exception.
	 * 
	 * @param message
	 *          the message
	 */
	public AnnotatedMethodException(String message) {
		super(message);
		this.c = null;
	}

	/**
	 * Instantiates a new annotated method exception.
	 * 
	 * @param c
	 *          the c
	 * @param message
	 *          the message
	 */
	public AnnotatedMethodException(Class<?> c, String message) {
		super(c, message);
		this.c = c;
	}

	/**
	 * Instantiates a new annotated method exception.
	 * 
	 * @param cause
	 *          the cause
	 */
	public AnnotatedMethodException(Throwable cause) {
		super(cause);
		this.c = null;

	}

	/**
	 * Instantiates a new annotated method exception.
	 * 
	 * @param c
	 *          the c
	 * @param cause
	 *          the cause
	 */
	public AnnotatedMethodException(Class<?> c, Throwable cause) {
		super(c, cause);
		this.c = c;

	}

	/**
	 * Instantiates a new annotated method exception.
	 * 
	 * @param message
	 *          the message
	 * @param cause
	 *          the cause
	 */
	public AnnotatedMethodException(String message, Throwable cause) {
		super(message, cause);

		this.c = null;
	}

	/**
	 * Instantiates a new annotated method exception.
	 * 
	 * @param c
	 *          the c
	 * @param message
	 *          the message
	 * @param cause
	 *          the cause
	 */
	public AnnotatedMethodException(Class<?> c, String message, Throwable cause) {
		super(c, message, cause);
		this.c = c;
	}

	/**
	 * Gets the header.
	 * 
	 * @return the header
	 * @see org.jnetpcap.packet.structure.HeaderDefinitionError#getHeader()
	 */
	public Class<?> getHeader() {
		return c;
	}
}
