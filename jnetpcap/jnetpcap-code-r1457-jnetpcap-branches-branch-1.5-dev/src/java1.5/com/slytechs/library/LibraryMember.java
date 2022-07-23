/**
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
package com.slytechs.library;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

// TODO: Auto-generated Javadoc
/**
 * The Interface LibraryMember.
 * 
 * @author Sly Technologies, Inc.
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface LibraryMember {

	/**
	 * Version since members introduction.
	 * 
	 * @return the int
	 */
	String api() default Library.API;;

	/**
	 * In.
	 * 
	 * @return the class
	 */
	String[] value() default { };
}
