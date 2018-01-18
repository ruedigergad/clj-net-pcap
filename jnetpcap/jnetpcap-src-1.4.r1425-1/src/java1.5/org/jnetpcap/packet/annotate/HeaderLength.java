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
package org.jnetpcap.packet.annotate;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

// TODO: Auto-generated Javadoc
/**
 * The Interface HeaderLength.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Target(ElementType.METHOD)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface HeaderLength {

	/**
	 * Table with constants for each type of get length methods supported.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Type {

		/** Method returns length of the prefix that is infront of the header. */
		PREFIX,

		/** Method returns length of the header. */
		HEADER,

		/**
		 * Method returns the length of the gap that is in between the header and
		 * the payload.
		 */
		GAP,

		/**
		 * Method returns the length of payload that follows the header and the gap.
		 */
		PAYLOAD,

		/** Method returns the length of the postfix that follows the payload. */
		POSTFIX
	}

	/**
	 * Static length of a header. A return value of -1 means, that length is not
	 * static but dynamic and the dynamic method must be invoked.
	 * 
	 * @return static length of this header or -1 if length is dynamic
	 */
//	int value() default -1;

	/**
	 * Sets the type of length getter method this is. The default is that the
	 * length getter is for a header.
	 * 
	 * @return type of length getter method
	 */
	Type value() default Type.HEADER;
}
