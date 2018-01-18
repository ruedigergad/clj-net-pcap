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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Field.Property;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

// TODO: Auto-generated Javadoc
/**
 * The Class AnnotatedField.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedField {

	/**
	 * Check singature.
	 * 
	 * @param c
	 *          the c
	 * @param method
	 *          the method
	 */
	private static void checkSingature(Class<? extends JHeader> c, Method method) {

		if (method.isAnnotationPresent(Field.class) == false) {
			throw new AnnotatedMethodException(c,
					"missing @Field annotation on field " + method.getName());
		}
	}

	/**
	 * Inspect enum constant.
	 * 
	 * @param field
	 *          the field
	 * @param enumAnnotation
	 *          the enum annotation
	 * @param methods
	 *          the methods
	 * @param c
	 *          the c
	 * @return the annotated field
	 */
	public static AnnotatedField inspectEnumConstant(String field,
			Field enumAnnotation,
			Map<Property, AnnotatedFieldMethod> methods,
			Class<?> c) {

		if (methods.containsKey(Property.VALUE) == false) {
			throw new AnnotatedMethodException(c,
					"missing value getter method for field based on enum constant: "
							+ field);
		}

		if (methods.containsKey(Property.LENGTH) == false) {
			throw new AnnotatedMethodException(c,
					"missing length getter method for field based on enum constant: "
							+ field);
		}

		if (methods.containsKey(Property.OFFSET) == false) {
			throw new AnnotatedMethodException(c,
					"missing offset getter method for field based on enum constant: "
							+ field);
		}

		return new AnnotatedField(field, enumAnnotation, methods, c);
	}

	/**
	 * Inspect method.
	 * 
	 * @param c
	 *          the c
	 * @param m
	 *          the m
	 * @return the annotated field
	 */
	public static AnnotatedField inspectMethod(Class<? extends JHeader> c,
			Method m) {

		checkSingature(c, m);

		AnnotatedField field = new AnnotatedField(m);

		return field;
	}

	/**
	 * Map format to style.
	 * 
	 * @param format
	 *          the format
	 * @return the style
	 */
	private static Style mapFormatToStyle(String format) {
		if (format.contains("%s[]")) {
			return Style.STRING_ARRAY;
		} else if (format.contains("%s")) {
			return Style.STRING;
		} else if (format.contains("%b")) {
			return Style.BOOLEAN;
		} else if (format.contains("%d")) {
			return Style.INT_DEC;
		} else if (format.contains("%d[]")) {
			return Style.INT_DEC_ARRAY;
		} else if (format.contains("%lx")) {
			return Style.LONG_HEX;
		} else if (format.contains("%x")) {
			return Style.INT_HEX;
		} else if (format.contains("#x32#")) {
			return Style.INT_HEX;
		} else if (format.contains("#ip4#")) {
			return Style.BYTE_ARRAY_IP4_ADDRESS;
		} else if (format.contains("#ip4[]#")) {
			return Style.BYTE_ARRAY_ARRAY_IP4_ADDRESS;
		} else if (format.contains("#ip6#")) {
			return Style.BYTE_ARRAY_IP6_ADDRESS;
		} else if (format.contains("#mac#")) {
			return Style.BYTE_ARRAY_COLON_ADDRESS;
		} else if (format.contains("#hexdump#")) {
			return Style.BYTE_ARRAY_HEX_DUMP;
		} else if (format.contains("#textdump#")) {
			return Style.STRING_TEXT_DUMP;
		} else if (format.contains("#bitfield#")) {
			return Style.INT_BITS;
		} else if (format.contains("#timestamp#")) {
			return Style.TIMESTAMP;
		} else if (format.contains("#timestamp_seconds#")) {
			return Style.TIMESTAMP_SECONDS;
		} else if (format.contains("#octets#")) {
			return Style.BYTE_ARRAY_OCTET_STREAM;
		} else {
			return Style.STRING;
		}
	}

	/** The annotation. */
	private final Field annotation;

	/** The declaring class. */
	private final Class<?> declaringClass;

	/** The method. */
	private final Method method;

	/** The runtime. */
	private final AnnotatedFieldRuntime runtime;

	/** The sub fields. */
	private final List<AnnotatedField> subFields =
			new ArrayList<AnnotatedField>();

	/** The name. */
	private String name;

	/**
	 * Instantiates a new annotated field.
	 * 
	 * @param method
	 *          the method
	 */
	private AnnotatedField(Method method) {
		this.method = method;
		this.annotation = method.getAnnotation(Field.class);
		this.runtime = new AnnotatedFieldRuntime(this);
		this.declaringClass = method.getDeclaringClass();
	}

	/**
	 * Instantiates a new annotated field.
	 * 
	 * @param name
	 *          the name
	 * @param enumAnnotation
	 *          the enum annotation
	 * @param methods
	 *          the methods
	 * @param declaringClass
	 *          the declaring class
	 */
	public AnnotatedField(String name, Field enumAnnotation,
			Map<Property, AnnotatedFieldMethod> methods, Class<?> declaringClass) {

		this.name = name;
		this.method = methods.get(Property.VALUE).method;
		this.annotation = enumAnnotation;
		this.runtime = new AnnotatedFieldRuntime(this);
		this.declaringClass = method.getDeclaringClass();

		this.runtime.setFunction(methods);
	}

	/**
	 * Adds the sub field.
	 * 
	 * @param field
	 *          the field
	 */
	public void addSubField(AnnotatedField field) {
		this.subFields.add(field);
	}

	/**
	 * Finish processing.
	 * 
	 * @param errors
	 *          the errors
	 */
	public void finishProcessing(List<HeaderDefinitionError> errors) {
		runtime.finishProcessing(errors);

		for (AnnotatedField field : subFields) {
			field.finishProcessing(errors);
		}
	}

	/**
	 * Gets the declaring class.
	 * 
	 * @return the declaring class
	 */
	public Class<?> getDeclaringClass() {
		return this.declaringClass;
	}

	/**
	 * Gets the description.
	 * 
	 * @return the description
	 */
	public String getDescription() {
		return annotation.description();
	}

	/**
	 * Gets the display.
	 * 
	 * @return the display
	 */
	public final String getDisplay() {
		return (annotation.display().length() == 0) ? getName() : annotation
				.display();
	}

	/**
	 * Gets the format.
	 * 
	 * @return the format
	 */
	public final String getFormat() {
		if (isSubField() && annotation.format().length() == 0) {
			return "#bitfield#";
		}
		return (annotation.format().length() == 0) ? "%s" : annotation.format();
	}

	/**
	 * Gets the length.
	 * 
	 * @return the length
	 */
	public int getLength() {
		return annotation.length();
	}

	/**
	 * Gets the mask.
	 * 
	 * @return the mask
	 */
	public long getMask() {
		return annotation.mask();
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
	 * Gets the name.
	 * 
	 * @return the name
	 */
	public final String getName() {
		if (this.name != null) {
			return name;
		}
		return (annotation.name().length() == 0) ? method.getName() : annotation
				.name();
	}

	/**
	 * Gets the nicname.
	 * 
	 * @return the nicname
	 */
	public final String getNicname() {
		return (annotation.nicname().length() == 0) ? getName() : annotation
				.nicname();
	}

	/**
	 * Gets the offset.
	 * 
	 * @return the offset
	 */
	public int getOffset() {
		return annotation.offset();
	}

	/**
	 * Gets the parent.
	 * 
	 * @return the parent
	 */
	public String getParent() {
		return annotation.parent();
	}

	/**
	 * Gets the priority.
	 * 
	 * @return the priority
	 */
	public Priority getPriority() {
		return annotation.priority();
	}

	/**
	 * Gets the runtime.
	 * 
	 * @return the runtime
	 */
	public final AnnotatedFieldRuntime getRuntime() {
		return this.runtime;
	}

	/**
	 * Gets the style.
	 * 
	 * @return the style
	 */
	public Style getStyle() {
		if (isSubField()) {
			return Style.INT_BITS;
		}

		return mapFormatToStyle(getFormat());
	}

	/**
	 * Gets the sub fields.
	 * 
	 * @return the sub fields
	 */
	public List<AnnotatedField> getSubFields() {
		return subFields;
	}

	/**
	 * Gets the units.
	 * 
	 * @return the units
	 */
	public String getUnits() {
		return annotation.units();
	}

	/**
	 * Checks if is sub field.
	 * 
	 * @return true, if is sub field
	 */
	public boolean isSubField() {
		return annotation.parent().length() != 0;
	}
}
