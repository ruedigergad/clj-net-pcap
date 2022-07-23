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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.annotate.Field.Property;

// TODO: Auto-generated Javadoc
/**
 * The Class AnnotatedFieldRuntime.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedFieldRuntime {

	/** The map. */
	private final Map<Property, AnnotatedFieldMethod> map =
	    new HashMap<Property, AnnotatedFieldMethod>();

	/** The parent. */
	private final AnnotatedField parent;

	/**
	 * Instantiates a new annotated field runtime.
	 * 
	 * @param parent
	 *          the parent
	 */
	public AnnotatedFieldRuntime(AnnotatedField parent) {
		this.parent = parent;

	}

	/**
	 * Finish processing.
	 * 
	 * @param errors
	 *          the errors
	 */
	public void finishProcessing(List<HeaderDefinitionError> errors) {

		/*
		 * Time to optimize and fill in the blanks if there are any
		 */
		for (Property f : Property.values()) {

			try {
				if (map.containsKey(f) == false) {
					map.put(f, AnnotatedFieldMethod.generateFunction(f, parent));
				}
			} catch (HeaderDefinitionError e) {
				errors.add(e);
			}
		}
	}

	/**
	 * Gets the function map.
	 * 
	 * @return the function map
	 */
	public Map<Property, AnnotatedFieldMethod> getFunctionMap() {
		return map;
	}

	/**
	 * Sets the function.
	 * 
	 * @param method
	 *          the new function
	 */
	public void setFunction(AnnotatedFieldMethod method) {
		final Property function = method.getFunction();

		if (map.containsKey(function)) {
			throw new HeaderDefinitionError(method.getMethod().getDeclaringClass(),
			    "duplicate " + function + " method declarations for field "
			        + parent.getName());
		}

		/*
		 * Set default values if they were declared with the @Field annotation. This
		 * saves having to make the actual call to the header.
		 */
		if (method.isMapped == false) {
			method.configFromField(parent);
		}
		map.put(function, method);
	}

	/**
	 * Sets the function.
	 * 
	 * @param methods
	 *          the methods
	 */
	public void setFunction(Map<Property, AnnotatedFieldMethod> methods) {
		for (AnnotatedFieldMethod f : methods.values()) {
			setFunction(f);
		}
	}

}
