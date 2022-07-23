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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.JBinding;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.annotate.Bind;

/**
 * The Class AnnotatedBinding.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedBinding implements JBinding {

	/** The Constant cache. */
	private final static Map<Class<?>, JBinding[]> cache =
			new HashMap<Class<?>, JBinding[]>();

	/**
	 * Clear cache.
	 */
	public static void clearCache() {
		cache.clear();
	}

	/**
	 * Creates the header from class.
	 * 
	 * @param c
	 *            the c
	 * @return the j header
	 */
	private static JHeader createHeaderFromClass(Class<? extends JHeader> c) {
		try {
			JHeader header = c.newInstance();
			return header;
		} catch (InstantiationException e) {
			throw new HeaderDefinitionError(c,
					"problem in the default constructor", e);
		} catch (IllegalAccessException e) {
			throw new HeaderDefinitionError(c,
					"problem in the default constructor", e);
		}
	}

	/**
	 * Inspect class.
	 * 
	 * @param c
	 *            the c
	 * @param errors
	 *            the errors
	 * @return the j binding[]
	 */
	public synchronized static JBinding[] inspectClass(Class<?> c,
			List<HeaderDefinitionError> errors) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedBindMethod[] bindMethods =
				AnnotatedBindMethod.inspectClass(c, errors);

		return createBindings(c, bindMethods, errors);
	}

	/**
	 * Creates the bindings.
	 * 
	 * @param c
	 *            the c
	 * @param bindMethods
	 *            the bind methods
	 * @param errors
	 *            the errors
	 * @return the j binding[]
	 */
	private static JBinding[] createBindings(Class<?> c,
			AnnotatedBindMethod[] bindMethods,
			List<HeaderDefinitionError> errors) {

		List<JBinding> list = new ArrayList<JBinding>();
		Class<? extends JHeader> target = null;

		for (AnnotatedBindMethod boundMethod : bindMethods) {

			try {

				Bind bind = boundMethod.getMethod().getAnnotation(Bind.class);
				target = bind.to();
				Class<? extends JHeader> source = bind.from();
				Class<? extends JHeader>[] dependencies = bind.dependencies();

				list.add(new AnnotatedBinding(c, source, target, boundMethod,
						dependencies));

			} catch (AnnotatedMethodException e) {
				errors.add(e);
			}

		}

		JBinding[] bindings = list.toArray(new JBinding[list.size()]);
		cache.put(c, bindings);

		return bindings;
	}

	/**
	 * Inspect j header class.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param c
	 *            the c
	 * @param errors
	 *            the errors
	 * @return the j binding[]
	 */
	public static <T extends JHeader> JBinding[] inspectJHeaderClass(
			Class<T> c, List<HeaderDefinitionError> errors) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedBindMethod[] bindMethods =
				AnnotatedBindMethod.inspectJHeaderClass(c, errors);

		Class<T> source = c;
		List<JBinding> list = new ArrayList<JBinding>();
		Class<? extends JHeader> target = null;

		for (AnnotatedBindMethod boundMethod : bindMethods) {

			try {

				Bind bind = boundMethod.getMethod().getAnnotation(Bind.class);
				target = bind.to();
				Class<? extends JHeader>[] dependencies = bind.dependencies();

				list.add(new AnnotatedBinding(c, source, target, boundMethod,
						dependencies));

			} catch (AnnotatedMethodException e) {
				errors.add(e);
			}
		}

		JBinding[] bindings = list.toArray(new JBinding[list.size()]);
		cache.put(c, bindings);

		return bindings;
	}

	/** The annotated bound. */
	private final AnnotatedBindMethod annotatedBound;

	/** The definition class. */
	private final Class<?> definitionClass;

	/** The dependencies. */
	protected final int[] dependencies;

	/**
	 * Our working protocol header that we use to peer with packet and dispatch
	 * to isBound method.
	 */
	private final ThreadLocal<JHeader> headerPool;

	/** The source id. */
	private final int sourceId;

	/** The target class. */
	private final Class<? extends JHeader> targetClass;

	/** The target id. */
	private final int targetId;

	/**
	 * Instantiates a new annotated binding.
	 * 
	 * @param definitionClass
	 *            the definition class
	 * @param source
	 *            the source
	 * @param target
	 *            the target
	 * @param bindingMethod
	 *            the binding method
	 * @param dependencies
	 *            the dependencies
	 */
	private AnnotatedBinding(Class<?> definitionClass,
			Class<? extends JHeader> source, Class<? extends JHeader> target,
			AnnotatedBindMethod bindingMethod,
			Class<? extends JHeader>... dependencies) {

		this.definitionClass = definitionClass;
		this.targetClass = target;
		this.annotatedBound = bindingMethod;
		this.dependencies = new int[dependencies.length];
		this.sourceId = JRegistry.lookupId(source);
		this.targetId = JRegistry.lookupId(target);

		/*
		 * Convert dependencies array of classes to array int IDs
		 */
		int i = 0;
		for (Class<? extends JHeader> c : dependencies) {
			this.dependencies[i++] = JRegistry.lookupId(c);
		}

		headerPool = new ThreadLocal<JHeader>() {

			@Override
			protected JHeader initialValue() {
				return createHeaderFromClass(targetClass);
			}

		};
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#getSourceId()
	 */
	/**
	 * Gets the source id.
	 * 
	 * @return the source id
	 * @see org.jnetpcap.packet.JBinding#getSourceId()
	 */
	public int getSourceId() {
		return this.sourceId;
	}

	/**
	 * Gets the target class.
	 * 
	 * @return the target class
	 */
	public Class<? extends JHeader> getTargetClass() {
		return targetClass;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#getTargetId()
	 */
	/**
	 * Gets the target id.
	 * 
	 * @return the target id
	 * @see org.jnetpcap.packet.JBinding#getTargetId()
	 */
	public int getTargetId() {
		return targetId;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#isBound(org.jnetpcap.packet.JPacket,
	 * int)
	 */
	/**
	 * Checks if is bound.
	 * 
	 * @param packet
	 *            the packet
	 * @param offset
	 *            the offset
	 * @return true, if is bound
	 * @see org.jnetpcap.packet.JBinding#isBound(org.jnetpcap.packet.JPacket,
	 *      int)
	 */
	public boolean isBound(JPacket packet, int offset) {

		/*
		 * Bug fix#133 Wrong assumption about multiplicity of headers
		 */
		final JHeader header = headerPool.get();
		
		/*
		 * How many header instances are in there?
		 */
		final int count = packet.getState().getInstanceCount(header.getId());

		if (count == 1) {
			packet.getHeader(header);
		} else { // More then 1, find which instance
			for (int i = 0; i < count; i ++) {
				packet.getHeader(header, i);
				if (header.getPayloadOffset() == offset) {
					break;
				}
			}
		}

		return header.isHeaderTruncated() == false
				&& annotatedBound.isBound(packet, offset, header);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JDependency#listDependencies()
	 */
	/**
	 * List dependencies.
	 * 
	 * @return the int[]
	 * @see org.jnetpcap.packet.JBinding#listDependencies()
	 */
	public int[] listDependencies() {
		return dependencies;
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		String def = this.definitionClass.getSimpleName();
		String method = this.annotatedBound.getMethod().getName();
		String target = this.targetClass.getSimpleName();

		return def + "." + method + "(JPacket packet, " + target + " header):"
				+ "boolean";
	}

	/**
	 * Inspect class.
	 * 
	 * @param bindingSuite
	 *            the binding suite
	 * @param errors
	 *            the errors
	 * @return the j binding[]
	 */
	public static JBinding[] inspectClass(Object bindingSuite,
			List<HeaderDefinitionError> errors) {
		return inspectClass(bindingSuite.getClass(), errors);
	}

	/**
	 * Inspect object.
	 * 
	 * @param object
	 *            the object
	 * @param errors
	 *            the errors
	 * @return the j binding[]
	 */
	public static JBinding[] inspectObject(Object object,
			List<HeaderDefinitionError> errors) {

		Class<?> c = object.getClass();

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedBindMethod[] bindMethods =
				AnnotatedBindMethod.inspectObject(object, errors);

		return createBindings(c, bindMethods, errors);

	}

}
