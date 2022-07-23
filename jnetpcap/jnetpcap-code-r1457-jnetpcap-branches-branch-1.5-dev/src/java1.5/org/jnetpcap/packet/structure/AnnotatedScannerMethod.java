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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScan;
import org.jnetpcap.packet.annotate.Scanner;

/**
 * The Class AnnotatedScannerMethod.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedScannerMethod
    extends AnnotatedMethod {

	/** The Constant cache. */
	private final static Map<Class<?>, AnnotatedScannerMethod[]> cache =
	    new HashMap<Class<?>, AnnotatedScannerMethod[]>();

	/**
	 * Inspect j header class.
	 * 
	 * @param c
	 *          the c
	 * @return the annotated scanner method[]
	 */
	public synchronized static AnnotatedScannerMethod[] inspectJHeaderClass(
	    Class<? extends JHeader> c) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		final Method[] ms = getMethods(c, Scanner.class);

		if (ms.length > 1) {
			throw new HeaderDefinitionError(c, "too many scanners defined");

		} else if (ms.length == 1) {
			AnnotatedScannerMethod[] m =
			    new AnnotatedScannerMethod[] { new AnnotatedScannerMethod(ms[0], c) };
			cache.put(c, m);

			return m;

		} else {
			AnnotatedScannerMethod[] m = new AnnotatedScannerMethod[0];
			cache.put(c, m);

			return m;
		}
	}

	/**
	 * Inspect class.
	 * 
	 * @param c
	 *          the c
	 * @return the annotated scanner method[]
	 */
	public synchronized static AnnotatedScannerMethod[] inspectClass(Class<? extends JHeader> c) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		List<AnnotatedScannerMethod> list =
		    new ArrayList<AnnotatedScannerMethod>(20);

		for (Method method : getMethods(c, Scanner.class)) {
			Scanner a = method.getAnnotation(Scanner.class);
			Class<? extends JHeader> clazz =
			    (a.value() == JHeader.class) ? c : a.value();

			if (JHeader.class.isAssignableFrom(c) == false) {
				throw new HeaderDefinitionError(c, "non JHeader based classes, "
				    + "must declare protocol class in @Scanner annotation");
			}

			list.add(new AnnotatedScannerMethod(method, clazz));
		}

		AnnotatedScannerMethod[] m =
		    list.toArray(new AnnotatedScannerMethod[list.size()]);
		cache.put(c, m);

		return m;
	}

	/**
	 * Inspect object.
	 * 
	 * @param container
	 *          the container
	 * @return the annotated scanner method[]
	 */
	public synchronized static AnnotatedScannerMethod[] inspectObject(Object container) {
		Class<?> c = container.getClass();

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		List<AnnotatedScannerMethod> list =
		    new ArrayList<AnnotatedScannerMethod>(20);

		for (Method method : getMethods(c, Scanner.class)) {
			Scanner a = method.getAnnotation(Scanner.class);
			if (a.value() == JHeader.class) {
				throw new HeaderDefinitionError(c, "non JHeader based classes, "
				    + "must declare protocol class in @Scanner annotation");
			}

			list.add(new AnnotatedScannerMethod(method, a.value(), container));
		}

		AnnotatedScannerMethod[] m =
		    list.toArray(new AnnotatedScannerMethod[list.size()]);
		cache.put(c, m);

		return m;
	}

	/** The id. */
	private final int id;

	/**
	 * Instantiates a new annotated scanner method.
	 * 
	 * @param method
	 *          the method
	 * @param c
	 *          the c
	 */
	private AnnotatedScannerMethod(Method method, Class<? extends JHeader> c) {
		super(method);

		this.id = JRegistry.lookupId(c);
	}

	/**
	 * Instantiates a new annotated scanner method.
	 * 
	 * @param method
	 *          the method
	 * @param c
	 *          the c
	 * @param container
	 *          the container
	 */
	public AnnotatedScannerMethod(Method method, Class<? extends JHeader> c,
	    Object container) {
		super(method, container);

		this.id = JRegistry.lookupId(c);
	}

	/**
	 * Scan.
	 * 
	 * @param scan
	 *          the scan
	 */
	public void scan(JScan scan) {
		try {
			method.invoke(object, scan);

		} catch (final IllegalArgumentException e) {
			throw new IllegalStateException(e);
		} catch (final IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (final InvocationTargetException e) {
			throw new AnnotatedMethodException(declaringClass, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.annotate.AnnotatedMethod#validateSignature(java.lang.reflect.Method)
	 */
	/**
	 * Validate signature.
	 * 
	 * @param method
	 *          the method
	 * @see org.jnetpcap.packet.structure.AnnotatedMethod#validateSignature(java.lang.reflect.Method)
	 */
	@Override
	protected void validateSignature(Method method) {
		final Class<?> declaringClass = method.getDeclaringClass();

		if (method.isAnnotationPresent(Scanner.class) == false) {
			throw new AnnotatedMethodException(declaringClass,
			    "@Scanner annotation missing for " + method.getName() + "()");
		}

		/*
		 * Now make sure it has the right signature of: <code>static int
		 * name(JBuffer, int)</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if (sig.length != 1 || sig[0] != JScan.class) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if (object == null && (method.getModifiers() & Modifier.STATIC) == 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " must be declared static");
		}
	}

	/**
	 * Gets the id.
	 * 
	 * @return the id
	 */
	public int getId() {
		return this.id;
	}
}
