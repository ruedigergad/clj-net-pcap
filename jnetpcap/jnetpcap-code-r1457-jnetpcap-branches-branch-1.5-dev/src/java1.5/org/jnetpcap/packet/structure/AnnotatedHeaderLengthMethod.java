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
import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.HeaderLength.Type;

// TODO: Auto-generated Javadoc
/**
 * The Class AnnotatedHeaderLengthMethod.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedHeaderLengthMethod
    extends
    AnnotatedMethod {

	/** The Constant cache. */
	private final static Map<Class<?>, AnnotatedHeaderLengthMethod[]> cache =
	    new HashMap<Class<?>, AnnotatedHeaderLengthMethod[]>();

	/**
	 * Inspect annotations within the class for length methods.
	 * 
	 * @param c
	 *          class to inspect
	 * @return array containing length methods for various header "record"
	 *         sub-structures
	 */
	public synchronized static AnnotatedHeaderLengthMethod[] inspectClass(
	    Class<? extends JHeader> c) {

		/*
		 * Check if we have this method cached for this class.
		 */
		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedHeaderLengthMethod[] methods =
		    new AnnotatedHeaderLengthMethod[HeaderLength.Type.values().length];

		Header header = c.getAnnotation(Header.class);
		if (header != null && header.length() != -1) {
			methods[HeaderLength.Type.HEADER.ordinal()] =
			    new AnnotatedHeaderLengthMethod(c, header.length(),
			        HeaderLength.Type.HEADER);
		}

		if (header != null && header.prefix() != -1) {
			methods[HeaderLength.Type.PREFIX.ordinal()] =
			    new AnnotatedHeaderLengthMethod(c, header.prefix(),
			        HeaderLength.Type.PREFIX);
		}

		if (header != null && header.gap() != -1) {
			methods[HeaderLength.Type.GAP.ordinal()] =
			    new AnnotatedHeaderLengthMethod(c, header.gap(),
			        HeaderLength.Type.GAP);
		}

		if (header != null && header.payload() != -1) {
			methods[HeaderLength.Type.PAYLOAD.ordinal()] =
			    new AnnotatedHeaderLengthMethod(c, header.payload(),
			        HeaderLength.Type.PAYLOAD);
		}

		if (header != null && header.postfix() != -1) {
			methods[HeaderLength.Type.POSTFIX.ordinal()] =
			    new AnnotatedHeaderLengthMethod(c, header.postfix(),
			        HeaderLength.Type.POSTFIX);
		}

		for (Method method : getMethods(c, HeaderLength.class)) {

			HeaderLength hl = method.getAnnotation(HeaderLength.class);

			if (methods[hl.value().ordinal()] != null) {
				throw new AnnotatedMethodException(c, "duplicate: "
				    + methods[hl.value().ordinal()] + " property and " + method.getName()
				    + "() method");
			}

			checkSignature(method);

			methods[hl.value().ordinal()] =
			    new AnnotatedHeaderLengthMethod(method, hl.value());
		}

		if (methods[HeaderLength.Type.HEADER.ordinal()] == null) {
			throw new AnnotatedMethodException(c,
			    "@HeaderLength annotated method not found");
		}

		cache.put(c, methods);
		return methods;
	}

	/** The static length. */
	private int staticLength;

	/** The type. */
	private final Type type;

	/**
	 * Instantiates a new annotated header length method.
	 * 
	 * @param method
	 *          the method
	 * @param type
	 *          the type
	 */
	private AnnotatedHeaderLengthMethod(Method method, HeaderLength.Type type) {
		super(method);
		this.type = type;

		this.staticLength = -1;
	}

	/**
	 * Instantiates a new annotated header length method.
	 * 
	 * @param c
	 *          the c
	 * @param length
	 *          the length
	 * @param type
	 *          the type
	 */
	public AnnotatedHeaderLengthMethod(
	    Class<? extends JHeader> c,
	    int length,
	    HeaderLength.Type type) {
		this.staticLength = length;
		this.type = type;
	}

	/**
	 * Gets the header length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the header length
	 */
	public int getHeaderLength(JBuffer buffer, int offset) {

		if (this.staticLength != -1) {
			return this.staticLength;
		}

		/*
		 * Invoke the static method: <code>public static int method(JBuffer, int)</code>
		 */
		try {
			int length = (int) (Integer) this.method.invoke(null, buffer, offset);
			return length;
		} catch (IllegalArgumentException e) {
			throw new IllegalStateException(e);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new AnnotatedMethodException(declaringClass, e.getCause());
		}
	}

	/**
	 * Gets the method.
	 * 
	 * @return the method
	 * @see org.jnetpcap.packet.structure.AnnotatedMethod#getMethod()
	 */
	public final Method getMethod() {
		return this.method;
	}

	/**
	 * Checks for static length.
	 * 
	 * @return true, if successful
	 */
	public boolean hasStaticLength() {
		return this.staticLength != -1;
	}

	/**
	 * Validate signature.
	 * 
	 * @param method
	 *          the method
	 * @see org.jnetpcap.packet.structure.AnnotatedMethod#validateSignature(java.lang.reflect.Method)
	 */
	protected void validateSignature(Method method) {
		checkSignature(method);
	}

	/**
	 * Check signature.
	 * 
	 * @param method
	 *          the method
	 */
	private static void checkSignature(Method method) {

		Class<?> declaringClass = method.getDeclaringClass();

		if (method.isAnnotationPresent(HeaderLength.class) == false) {
			throw new AnnotatedMethodException(declaringClass,
			    "@HeaderLength annotation missing for " + method.getName() + "()");
		}

		/*
		 * Now make sure it has the right signature of: <code>static int
		 * name(JBuffer, int)</code.
		 */
		Class<?>[] t = method.getParameterTypes();
		if (t.length != 2 || t[0] != JBuffer.class || t[1] != int.class
		    || method.getReturnType() != int.class) {

			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) == 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " must be declared static");

		}
	}

	/**
	 * Clear cache.
	 */
	public static void clearCache() {
		cache.clear();
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see org.jnetpcap.packet.structure.AnnotatedMethod#toString()
	 */
	public String toString() {
		if (method == null) {
			String property =
			    (type == HeaderLength.Type.HEADER) ? "length" : type.toString()
			        .toLowerCase();
			return "@Header(" + property + "=" + staticLength + ")";
		} else {
			return super.toString();
		}
	}

}
