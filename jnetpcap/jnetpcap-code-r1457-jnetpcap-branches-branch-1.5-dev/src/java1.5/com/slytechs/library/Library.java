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

/**
 * The Library requirements and helper information. This annotation is used to
 * make sure that proper prerequisite classes and their prereqs are loaded. The
 * class who's 'required' prerequisites are not loaded properly will also fail
 * to load. The class who's 'optional' prerequisites are not loaded will
 * continue to load, but is expected to provide a mechanism which allows checks
 * to be made, which parts of the classes API are not accessible due to
 * 'optional' requirements missing.
 * <p>
 * This is primarily used with providing support for multiple versions of an
 * API. The optional parts of the API are determined at runtime.
 * </p>
 * 
 * @author Sly Technologies, Inc.
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface Library {
	public static final String API = "API 0.0.0";

	String defaultAPI() default API;

	/**
	 * Required dependencies. The class will fail to load properly without the
	 * required dependencies.
	 * 
	 * @return the class[] array of classes which will be loaded ahead of this
	 *         class
	 */
	String[] jni() default { };

	String[] natives() default { };

	/**
	 * Optional dependencies. The class will load successfully but parts of its
	 * API may not be accessible due to optional dependencies missing. The class
	 * should provide a mechanism which will provide information about which parts
	 * of the API are not available.
	 * 
	 * @return the class[] array of classes which will be loaded ahead of this
	 *         class
	 */
	String[] optional() default { };

	String[] optionalNative() default { };

	/**
	 * (Optional) name of system library that this class is dependent on. The
	 * system library (shared native library), will first be loaded along with any
	 * required and optional prerequisites. The library is loaded using normal
	 * 
	 * @return the name of the system library {@link System#loadLibrary(String)}
	 *         call. In addition to loading the library, the library's partial
	 *         symbol table is read and matched up with native methods in the
	 *         class.
	 */
	Class<?>[] preload() default { };
}
