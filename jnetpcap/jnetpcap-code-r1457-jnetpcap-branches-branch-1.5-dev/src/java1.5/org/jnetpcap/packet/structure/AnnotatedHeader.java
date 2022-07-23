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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldSetter;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.Field.Property;
import org.jnetpcap.protocol.JProtocol.Suite;

// TODO: Auto-generated Javadoc
/**
 * The Class AnnotatedHeader.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedHeader {

	/** The Constant cache. */
	private final static Map<Class<?>, AnnotatedHeader> cache =
	    new HashMap<Class<?>, AnnotatedHeader>();

	/**
	 * Gets the sub header classes.
	 * 
	 * @param c
	 *          the c
	 * @param prefix
	 *          the prefix
	 * @return the sub header classes
	 */
	private static List<Class<?>> getSubHeaderClasses(Class<?> c, String prefix) {

		final List<Class<?>> list = new ArrayList<Class<?>>();

		for (final Class<?> s : c.getClasses()) {

			if (s == c) { // prevent infinate loop
				continue;
			}

			if (s.isAnnotationPresent(Header.class)) {
				list.add(s);

				/*
				 * We're interested in direct sub-header's and not sub-headers of
				 * sub-headers. Again, a sub header has @Header annotation on it, not
				 * just the java declaration class within a class. We're looking at the
				 * hierachy of @Header type sub-headers. Each sub-headers evaluates its
				 * own sub-headers in a seperate scan, that is why we stop here.
				 */
				continue;
			}

			list.addAll(getSubHeaderClasses(s, prefix + "." + s.getSimpleName()));
		}

		return list;
	}

	/** The description. */
	private String description;

	/**
	 * Inspect header annotation.
	 * 
	 * @param c
	 *          the c
	 * @param errors
	 *          the errors
	 * @return the annotated header
	 * @Header is optional on top level header. It defaults to class name as
	 *         header name
	 */
	private static AnnotatedHeader inspectHeaderAnnotation(
	    Class<? extends JHeader> c,
	    List<HeaderDefinitionError> errors) {

		AnnotatedHeader header = new AnnotatedHeader(c);

		if (c.isAnnotationPresent(Header.class)) {
			Header a = c.getAnnotation(Header.class);

			if (JHeader.class.isAssignableFrom(c) == false) {
				/*
				 * All headers must subclass JHeader.class, no exceptions.
				 */

				errors.add(new HeaderDefinitionError(c,
				    "header must subclass 'JHeader'"));
			}

			if (a.name().length() != 0) {
				header.name = a.name();
			} else {
				header.name = c.getSimpleName();
			}

			if (a.nicname().length() != 0) {
				header.nicname = a.nicname();
			} else {
				header.nicname = header.name;
			}

			if (a.description().length() != 0) {
				header.description = a.description();
			} else if (a.dlt().length != 0) {
				/*
				 * Description comes from libpcap itself :)
				 */
				header.description = a.dlt()[0].getDescription();

			} else {
				header.description = null;
			}

			if (a.id() != -1) {
				a.id();
			}

			if (a.parent() != JHeader.class) {
				header.parentClass = a.parent();
			}

			if (header.parentClass == null && c.getEnclosingClass() != null) {
				for (Class<?> p = c.getEnclosingClass(); p != null; p =
				    p.getEnclosingClass()) {

					if (p.isAnnotationPresent(Header.class)) {
						if (JHeader.class.isAssignableFrom(p) == false) {
							errors.add(new HeaderDefinitionError(c, "parentClass header '"
							    + p.getSimpleName() + "' must subclass 'JHeader'"));
							break;
						}

						header.parentClass = p.asSubclass(JHeader.class);
						break;
					}
				}
			}

		} else {
			errors.add(new HeaderDefinitionError(c,
			    "header missing @Header annotation"));
		}

		return header;
	}

	/**
	 * Inspect j header class.
	 * 
	 * @param c
	 *          the c
	 * @param errors
	 *          the errors
	 * @return the annotated header
	 */
	public synchronized static AnnotatedHeader inspectJHeaderClass(
	    Class<? extends JHeader> c,
	    List<HeaderDefinitionError> errors) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedHeader header = inspectHeaderAnnotation(c, errors);

		/*
		 * Prepare by extracting all annotated methods and putting them into their
		 * own buckets
		 */
		List<Method> fieldMethods = new ArrayList<Method>(50);
		List<Method> setterMethods = new ArrayList<Method>(50);
		List<Method> runtimeMethods = new ArrayList<Method>(50);
		List<Method> allMethods = new ArrayList<Method>(100);

		Map<String, AnnotatedField> fields =
		    new HashMap<String, AnnotatedField>(fieldMethods.size());

		/*
		 * Extract protected methods
		 */
		Class<?> p = c;
		while (p != Object.class) {
			allMethods.addAll(Arrays.asList(p.getDeclaredMethods()));

			p = p.getSuperclass();
		}

		for (Method m : allMethods) {
			if (m.isAnnotationPresent(Field.class)) {
				fieldMethods.add(m);
			}

			if (m.isAnnotationPresent(Dynamic.class)) {
				runtimeMethods.add(m);

				/*
				 * Allow the method to be invoked by JField directly
				 */
				m.setAccessible(true);
				// System.out.printf("AnnotatedHeader::Dynamic=%s %s\n", m.getName(), c
				// .getSimpleName());
			}

			if (m.isAnnotationPresent(FieldSetter.class)) {
				setterMethods.add(m);
			}
		}

		/*
		 * First process @Field methods, then later add runtimes
		 */
		for (Method m : fieldMethods) {
			try {
				AnnotatedField field = AnnotatedField.inspectMethod(c, m);

				// System.out.printf("field=%s\n", field.getName());

				if (fields.containsKey(field.getName())) {
					throw new HeaderDefinitionError(c, "duplicate field "
					    + field.getName());
				}

				fields.put(field.getName(), field);
			} catch (HeaderDefinitionError e) {
				errors.add(e);
			}
		}

		Map<Property, AnnotatedFieldMethod> defaultMethods =
		    new HashMap<Property, AnnotatedFieldMethod>();

		/*
		 * Second process @Dynamic marked methods
		 */
		for (Method m : runtimeMethods) {
			try {
				AnnotatedFieldMethod function = AnnotatedFieldMethod.inspectMethod(m);

				if (function.method.getParameterTypes().length == 1) {
					defaultMethods.put(function.getFunction(), function);
					function.setIsMapped(true);
					continue;
				}

				AnnotatedField field = fields.get(function.getFieldName());
				if (field == null) {
					throw new HeaderDefinitionError(c, "runtime can not find field "
					    + function.getFieldName());
				}

				field.getRuntime().setFunction(function);
			} catch (HeaderDefinitionError e) {
				errors.add(e);
			}
		}

		/**
		 * Handle 3 different cases of enum tables and enum constant field
		 * declarations. In this step we create the field and also assign the
		 * dynamic property getter methods since enum based fields do not use
		 * constant properties and never are field value getter methods themselves.
		 * Therefore the default dynamic methods must have already been seen and
		 * defined in the class hierarchy somewhere, otherwise its an error.
		 * 
		 * <pre>
		 * &#064;Field 
		 * public enum ABC {
		 * A,
		 * B,
		 * C,
		 * }
		 * 
		 * &#064;Field
		 * public enum ABC {
		 * A,
		 * &#064;Field B,
		 * C
		 * }
		 * 
		 * public enum ABC {
		 * &#064;Field A,
		 * &#064;Field B,
		 * &#064;Field C
		 * </pre>
		 */
		Field enumAnnotation = null;
		for (Class<?> e : c.getClasses()) {
			enumAnnotation = null; // reset

			if (e.isAnnotationPresent(Field.class) && e.isEnum()) {
				enumAnnotation = e.getAnnotation(Field.class); // Table wide

				for (Object element : e.getEnumConstants()) {
					String name = element.toString().replace('_', '-');
//					System.out.printf("enum name=%s\n", name);
					try {
						AnnotatedField field =
						    AnnotatedField.inspectEnumConstant(name, enumAnnotation,
						        defaultMethods, c);

						fields.put(name, field);
					} catch (AnnotatedMethodException er) {
						errors.add(er);
					}
				}
			}
		}

		/*
		 * Process sub-fields or compound fields
		 */
		;
		for (Iterator<AnnotatedField> i = fields.values().iterator(); i.hasNext();) {
			AnnotatedField field = i.next();
			try {
				if (field.isSubField() == false) {
					continue;
				}

				if (field.getParent().equals(field.getName())) {
					throw new HeaderDefinitionError(c,
					    "invalid parentClass name for sub-field " + field.getName());
				}

				AnnotatedField parent = fields.get(field.getParent());
				if (parent == null) {
					throw new HeaderDefinitionError(c, "can not find parentClass '"
					    + field.getParent() + "' for sub field '" + field.getName() + "'");
				}

				parent.addSubField(field);

				i.remove();

			} catch (HeaderDefinitionError e) {
				errors.add(e);
			}
		}

		/*
		 * Last, tell all the fields we are done processing and let them finish up
		 * whatever they need to
		 */
		for (AnnotatedField field : fields.values()) {
			field.finishProcessing(errors);
		}

		/*
		 * Check for sub-headers. We need to walk the entire class within class
		 * hierachy looking for classes marked with @Header annotation. Unless they
		 * have the "parentClass" parameter defined, they automatically become the
		 * sub-header of us. The sub-class must also extend JSubHeader class, if it
		 * doesn't we skip it and report an error.
		 */
		List<Class<?>> subClasses = getSubHeaderClasses(c, c.getSimpleName());
		List<AnnotatedHeader> subHeaders =
		    new ArrayList<AnnotatedHeader>(subClasses.size());
		for (Class<?> s : subClasses) {

			if (c == s) { // Prevent infinite loop
				continue;
			}

			if (JSubHeader.class.isAssignableFrom(s) == false) {
				errors.add(new HeaderDefinitionError(c, "skipping sub-header "
				    + s.getSimpleName()
				    + ". The sub-header must subclass JSubHeader class"));
				continue;
			}

			// System.out.printf("inspecting sub-header %s\n", s.getSimpleName());

			subHeaders
			    .add(inspectJHeaderClass(s.asSubclass(JSubHeader.class), errors));

		}

		header.saveSubHeaders(subHeaders.toArray(new AnnotatedHeader[subHeaders
		    .size()]));

		header.saveFields(fields.values()
		    .toArray(new AnnotatedField[fields.size()]));

		try {
			AnnotatedHeaderLengthMethod.inspectClass(c);
		} catch (AnnotatedMethodException e) {
			errors.add(new HeaderDefinitionError(c, e));
		}

		if (errors.isEmpty()) {
			cache.put(c, header);
		}

		return header;
	}

	/** The clazz. */
	private Class<? extends JHeader> clazz;

	/** The fields. */
	private AnnotatedField[] fields;

	/** The annotation. */
	private final Header annotation;

	/** The headers. */
	private AnnotatedHeader[] headers;

	/** The name. */
	private String name;

	/** The nicname. */
	private String nicname;

	/** The parent class. */
	private Class<? extends JHeader> parentClass = null;

	/** The parent. */
	private AnnotatedHeader parent;

	/**
	 * Instantiates a new annotated header.
	 * 
	 * @param c
	 *          the c
	 */
	private AnnotatedHeader(Class<? extends JHeader> c) {
		this.annotation = c.getAnnotation(Header.class);
		this.clazz = c;
	}

	/**
	 * Gets the fields.
	 * 
	 * @return the fields
	 */
	public AnnotatedField[] getFields() {
		return fields;
	}

	/**
	 * Gets the header class.
	 * 
	 * @return the header class
	 */
	public Class<? extends JHeader> getHeaderClass() {
		return this.clazz;
	}

	/**
	 * Gets the headers.
	 * 
	 * @return the headers
	 */
	public final AnnotatedHeader[] getHeaders() {
		return this.headers;
	}

	/**
	 * Gets the id.
	 * 
	 * @return the id
	 */
	public int getId() {
		return this.annotation.id();
	}

	/**
	 * Gets the name.
	 * 
	 * @return the name
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * Gets the dlt.
	 * 
	 * @return the dlt
	 */
	public PcapDLT[] getDlt() {
		return annotation.dlt();
	}

	/**
	 * Gets the suite.
	 * 
	 * @return the suite
	 */
	public Suite getSuite() {
		return annotation.suite();
	}
	
	/**
	 * Gets the nicname.
	 * 
	 * @return the nicname
	 */
	public final String getNicname() {
		return this.nicname;
	}

	/**
	 * Save fields.
	 * 
	 * @param fields
	 *          the fields
	 */
	private void saveFields(AnnotatedField[] fields) {
		this.fields = fields;

	}

	/**
	 * Save sub headers.
	 * 
	 * @param headers
	 *          the headers
	 */
	private void saveSubHeaders(AnnotatedHeader[] headers) {
		this.headers = headers;

		for (AnnotatedHeader header : headers) {
			header.setParent(this);
		}
	}

	/**
	 * Gets the parent.
	 * 
	 * @return the parent
	 */
	public final AnnotatedHeader getParent() {
		return this.parent;
	}

	/**
	 * Checks if is sub header.
	 * 
	 * @return true, if is sub header
	 */
	public boolean isSubHeader() {
		return this.parent != null;
	}

	/**
	 * Sets the parent.
	 * 
	 * @param parent
	 *          the new parent
	 */
	private void setParent(AnnotatedHeader parent) {
		this.parent = parent;
	}

	/**
	 * Gets the description.
	 * 
	 * @return the description
	 */
	public String getDescription() {
		return this.description;
	}
}
