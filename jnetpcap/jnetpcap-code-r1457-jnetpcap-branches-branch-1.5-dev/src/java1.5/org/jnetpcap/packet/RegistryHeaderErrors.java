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

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.structure.HeaderDefinitionError;

// TODO: Auto-generated Javadoc
/**
 * The Class RegistryHeaderErrors.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class RegistryHeaderErrors
    extends RegistryException {

	/** The errors. */
	private final List<HeaderDefinitionError> errors;

	/** The header class. */
	private final Class<? extends JHeader> headerClass;

	/**
	 * Gets the errors.
	 * 
	 * @return the errors
	 */
	public final HeaderDefinitionError[] getErrors() {
		return this.errors.toArray(new HeaderDefinitionError[errors.size()]);
	}

	/**
	 * Gets the header class.
	 * 
	 * @return the header class
	 */
	public final Class<? extends JHeader> getHeaderClass() {
		return this.headerClass;
	}

	/**
	 * Instantiates a new registry header errors.
	 * 
	 * @param headerClass
	 *          the header class
	 * @param errors
	 *          the errors
	 * @param msg
	 *          the msg
	 */
	public RegistryHeaderErrors(Class<? extends JHeader> headerClass,
	    List<HeaderDefinitionError> errors, String msg) {
		super(msg);
		this.headerClass = headerClass;

		this.errors = new ArrayList<HeaderDefinitionError>(errors);
	}

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -6414263503074702593L;

	/**
	 * Gets the message.
	 * 
	 * @return the message
	 * @see java.lang.Throwable#getMessage()
	 */
	@Override
	public String getMessage() {
		final StringBuilder out = new StringBuilder();

		for (final HeaderDefinitionError e : errors) {
			out.append(e.getMessage()).append('\n');
		}

		out.append('\n');
		out.append(super.getMessage());

		return out.toString();
	}

}
