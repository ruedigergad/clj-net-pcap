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

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * The Class AnnotatedMethod is a base class for all of the annotated methods
 * used through out jnetpcap. Provides various accessor to reflected methods
 * and works well with defined annotations for their intended purpose.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AnnotatedMethod {

	/**
	 * Gets the methods.
	 * 
	 * @param c
	 *            the c
	 * @param annotation
	 *            the annotation
	 * @return the methods
	 */
	public synchronized static Method[] getMethods(Class<?> c,
			Class<? extends Annotation> annotation) {

		final int hash = c.hashCode() + annotation.hashCode();
		if (cache.containsKey(hash)) {
			return cache.get(hash);
		}

		List<Method> methods = new ArrayList<Method>(50);
		for (Method method : c.getMethods()) {
			if (method.isAnnotationPresent(annotation)) {
				methods.add(method);
			}
		}

		Method[] m = methods.toArray(new Method[methods.size()]);
		cache.put(hash, m);
		return m;
	}

	/** The method. */
	protected final Method method;

	/** The is mapped. */
	protected boolean isMapped = false;

	/** The declaring class. */
	protected final Class<?> declaringClass;

	/** The object. */
	protected final Object object;

	/** The cache. */
	private static HashMap<Integer, Method[]> cache =
			new HashMap<Integer, Method[]>(20);

	/**
	 * Instantiates a new annotated method.
	 */
	public AnnotatedMethod() {
		this.method = null;
		this.declaringClass = null;
		this.object = null;
		this.isMapped = false;
	}

	/**
	 * Instantiates a new annotated method.
	 * 
	 * @param method
	 *            the method
	 */
	public AnnotatedMethod(Method method) {
		this.method = method;
		this.declaringClass = method.getDeclaringClass();
		this.object = null;

		validateSignature(method);

		/**
		 * BUG#3599244
		 */
		this.method.setAccessible(true);
	}

	/**
	 * Instantiates a new annotated method.
	 * 
	 * @param method
	 *            the method
	 * @param object
	 *            the object
	 */
	public AnnotatedMethod(Method method, Object object) {
		this.object = object;
		this.method = method;
		this.declaringClass = method.getDeclaringClass();

		/**
		 * BUG#3599244
		 */
		this.method.setAccessible(true);

	}

	/**
	 * Gets the method.
	 * 
	 * @return the method
	 */
	public Method getMethod() {
		return this.method;
	}

	/**
	 * Sets the checks if is mapped.
	 * 
	 * @param state
	 *            the new checks if is mapped
	 */
	public void setIsMapped(boolean state) {
		this.isMapped = state;
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		if (method == null) {
			return "";
		} else {
			return declaringClass.getSimpleName() + "." + method.getName()
					+ "()";
		}
	}

	/**
	 * Validate signature.
	 * 
	 * @param method
	 *            the method
	 */
	protected abstract void validateSignature(Method method);
}
