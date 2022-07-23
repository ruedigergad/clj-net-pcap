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
import java.util.List;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldDefinitionException;

// TODO: Auto-generated Javadoc
/**
 * The Class AnnotatedFieldMethod.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AnnotatedFieldMethod extends AnnotatedMethod {

	/**
	 * The Class BooleanFunction.
	 */
	private static class BooleanFunction extends AnnotatedFieldMethod {

		/** The has static value. */
		private boolean hasStaticValue = false;

		/** The value. */
		private boolean value;

		/**
		 * Instantiates a new boolean function.
		 * 
		 * @param field
		 *          the field
		 * @param function
		 *          the function
		 */
		public BooleanFunction(AnnotatedField field, Field.Property function) {
			super(field, function);

			setValue(true); // Static fields are always available

			field.getMethod().setAccessible(true);
		}

		/**
		 * Instantiates a new boolean function.
		 * 
		 * @param method
		 *          the method
		 * @param function
		 *          the function
		 */
		public BooleanFunction(Method method, Field.Property function) {
			super(method, function);

			method.setAccessible(true);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.jnetpcap.packet.AnnotatedFieldMethod#booleanMethod(org.jnetpcap.packet
		 * .JHeader)
		 */
		/**
		 * Boolean method.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return true, if successful
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#booleanMethod(org.jnetpcap.packet.JHeader,
		 *      java.lang.String)
		 */
		@Override
		public boolean booleanMethod(JHeader header, String name) {
			return execute(header, name);
		}

		/**
		 * Config from field.
		 * 
		 * @param field
		 *          the field
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#configFromField(org.jnetpcap.packet.structure.AnnotatedField)
		 */
		@Override
		public final void configFromField(AnnotatedField field) {

			switch (function) {
			case CHECK:
				break;

			default:
				throw new HeaderDefinitionError("Invalid Dynamic function type "
						+ function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
						+ function.name().toLowerCase() + "' property. [@Dynamic(Property."
						+ function.name() + ")]");
			}
		}

		/**
		 * Execute.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return true, if successful
		 */
		public boolean execute(JHeader header, String name) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				if (isMapped) {
					return (Boolean) method.invoke(header, name);
				} else {
					return (Boolean) method.invoke(header);
				}

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		/**
		 * Sets the value.
		 * 
		 * @param value
		 *          the new value
		 */
		private void setValue(boolean value) {
			hasStaticValue = true;
			this.value = value;
		}
	}

	/**
	 * The Class IntFunction.
	 */
	private static class IntFunction extends AnnotatedFieldMethod {

		/** The has static value. */
		private boolean hasStaticValue = false;

		/** The value. */
		private int value;

		/**
		 * Instantiates a new int function.
		 * 
		 * @param field
		 *          the field
		 * @param function
		 *          the function
		 */
		public IntFunction(AnnotatedField field, Field.Property function) {
			super(field, function);

			configFromField(field);

			field.getMethod().setAccessible(true);

		}

		/**
		 * Instantiates a new int function.
		 * 
		 * @param field
		 *          the field
		 * @param function
		 *          the function
		 * @param staticValue
		 *          the static value
		 */
		public IntFunction(AnnotatedField field, Field.Property function,
				int staticValue) {
			super(field, function);

			setValue(staticValue);

			field.getMethod().setAccessible(true);
		}

		/**
		 * Instantiates a new int function.
		 * 
		 * @param method
		 *          the method
		 * @param function
		 *          the function
		 */
		public IntFunction(Method method, Field.Property function) {
			super(method, function);

			method.setAccessible(true);
		}

		/**
		 * Config from field.
		 * 
		 * @param field
		 *          the field
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#configFromField(org.jnetpcap.packet.structure.AnnotatedField)
		 */
		@Override
		public final void configFromField(AnnotatedField field) {

			switch (function) {
			case LENGTH:
				if (field.getLength() != -1) {
					setValue(field.getLength());
				}
				break;

			case OFFSET:
				if (field.getOffset() != -1) {
					setValue(field.getOffset());
				}
				break;

			default:
				throw new HeaderDefinitionError("Invalid Dynamic function type "
						+ function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
						+ function.name().toLowerCase() + "' property. [@Field("
						+ function.name().toLowerCase() + "=<int>) or @Dynamic(Property."
						+ function.name() + ")]");
			}

		}

		/**
		 * Execute.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return the int
		 */
		public int execute(JHeader header, String name) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				if (isMapped) {
					return (Integer) method.invoke(header, name);
				} else {
					return (Integer) method.invoke(header);
				}

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.jnetpcap.packet.AnnotatedFieldMethod#intMethod(org.jnetpcap.packet
		 * .JHeader)
		 */
		/**
		 * Int method.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return the int
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#intMethod(org.jnetpcap.packet.JHeader,
		 *      java.lang.String)
		 */
		@Override
		public int intMethod(JHeader header, String name) {
			return execute(header, name);
		}

		/**
		 * Sets the value.
		 * 
		 * @param value
		 *          the new value
		 */
		private void setValue(int value) {
			hasStaticValue = true;
			this.value = value;
		}
	}

	/**
	 * The Class LongFunction.
	 */
	private static class LongFunction extends AnnotatedFieldMethod {

		/** The has static value. */
		private boolean hasStaticValue = false;

		/** The value. */
		private long value;

		/**
		 * Instantiates a new long function.
		 * 
		 * @param field
		 *          the field
		 * @param function
		 *          the function
		 */
		public LongFunction(AnnotatedField field, Field.Property function) {
			super(field, function);

			configFromField(field);

			field.getMethod().setAccessible(true);

		}

		/**
		 * Instantiates a new long function.
		 * 
		 * @param field
		 *          the field
		 * @param function
		 *          the function
		 * @param staticValue
		 *          the static value
		 */
		public LongFunction(AnnotatedField field, Field.Property function,
				long staticValue) {
			super(field, function);

			setValue(staticValue);

			field.getMethod().setAccessible(true);
		}

		/**
		 * Instantiates a new long function.
		 * 
		 * @param method
		 *          the method
		 * @param function
		 *          the function
		 */
		public LongFunction(Method method, Field.Property function) {
			super(method, function);

			method.setAccessible(true);
		}

		/**
		 * Config from field.
		 * 
		 * @param field
		 *          the field
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#configFromField(org.jnetpcap.packet.structure.AnnotatedField)
		 */
		@Override
		public final void configFromField(AnnotatedField field) {

			switch (function) {

			case MASK:

				setValue(field.getMask());
				break;

			default:
				throw new HeaderDefinitionError("Invalid Dynamic function type "
						+ function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
						+ function.name().toLowerCase() + "' property. [@Field("
						+ function.name().toLowerCase() + "=<int>) or @Dynamic(Property."
						+ function.name() + ")]");
			}

		}

		/**
		 * Execute.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return the long
		 */
		public long execute(JHeader header, String name) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				if (isMapped) {
					return (Long) method.invoke(header, name);
				} else {
					return (Long) method.invoke(header);
				}

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.jnetpcap.packet.AnnotatedFieldMethod#longMethod(org.jnetpcap.packet
		 * .JHeader)
		 */
		/**
		 * Long method.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return the long
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#longMethod(org.jnetpcap.packet.JHeader,
		 *      java.lang.String)
		 */
		@Override
		public long longMethod(JHeader header, String name) {
			return execute(header, name);
		}

		/**
		 * Sets the value.
		 * 
		 * @param mask
		 *          the new value
		 */
		private void setValue(long mask) {
			hasStaticValue = true;
			this.value = mask;
		}
	}

	/**
	 * The Class ObjectFunction.
	 */
	private static class ObjectFunction extends AnnotatedFieldMethod {

		/**
		 * Instantiates a new object function.
		 * 
		 * @param field
		 *          the field
		 * @param fuction
		 *          the fuction
		 */
		public ObjectFunction(AnnotatedField field, Field.Property fuction) {
			super(field, fuction, field.getMethod());

			field.getMethod().setAccessible(true);
		}

		/**
		 * Instantiates a new object function.
		 * 
		 * @param method
		 *          the method
		 * @param function
		 *          the function
		 */
		public ObjectFunction(Method method, Field.Property function) {
			super(method, function);

			method.setAccessible(true);
		}

		/**
		 * Config from field.
		 * 
		 * @param field
		 *          the field
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#configFromField(org.jnetpcap.packet.structure.AnnotatedField)
		 */
		@Override
		public final void configFromField(AnnotatedField field) {

			switch (function) {
			case VALUE:
				if (method == null) {
					throw new HeaderDefinitionError(field.getDeclaringClass(),
							"no method set for field value getter [" + field.getName() + "]");
				}
				break;

			default:
				throw new HeaderDefinitionError(field.getDeclaringClass(),
						"Invalid Dynamic function type " + function.toString());

			}

			if (method == null) {
				throw new FieldDefinitionException(field, "Missing field accessor '"
						+ function.name().toLowerCase() + "' property. [@Dynamic(Property."
						+ function.name() + ")]");
			}
		}

		/**
		 * Execute.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return the object
		 */
		public Object execute(JHeader header, String name) {

			try {
				if (isMapped) {
					return method.invoke(header, name);
				} else {
					return method.invoke(header);
				}

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e.getMessage(), e);
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.jnetpcap.packet.AnnotatedFieldMethod#objectMethod(org.jnetpcap.packet
		 * .JHeader)
		 */
		/**
		 * Object method.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return the object
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#objectMethod(org.jnetpcap.packet.JHeader,
		 *      java.lang.String)
		 */
		@Override
		public Object objectMethod(JHeader header, String name) {
			return execute(header, name);
		}
	}

	/**
	 * The Class StringFunction.
	 */
	private static class StringFunction extends AnnotatedFieldMethod {

		/** The has static value. */
		private boolean hasStaticValue = false;

		/** The value. */
		private String value;

		/**
		 * Instantiates a new string function.
		 * 
		 * @param field
		 *          the field
		 * @param function
		 *          the function
		 */
		public StringFunction(AnnotatedField field, Field.Property function) {
			super(field, function);

			field.getMethod().setAccessible(true);

			configFromField(field);
		}

		/**
		 * Instantiates a new string function.
		 * 
		 * @param method
		 *          the method
		 * @param function
		 *          the function
		 */
		public StringFunction(Method method, Field.Property function) {
			super(method, function);

			method.setAccessible(true);
		}

		/**
		 * Config from field.
		 * 
		 * @param field
		 *          the field
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#configFromField(org.jnetpcap.packet.structure.AnnotatedField)
		 */
		@Override
		public final void configFromField(AnnotatedField field) {

			switch (function) {
			case UNITS:
				if (field.getUnits().length() != 0) {
					setValue(field.getUnits());
				} else if (method == null) {
					setValue(null);
				}
				break;
			case DISPLAY:
				if (field.getDisplay().length() != 0) {
					setValue(field.getDisplay());
				} else if (method == null) {
					setValue(null);
				}
				break;

			case DESCRIPTION:
				if (field.getDescription().length() != 0) {
					setValue(field.getDescription());
				} else if (method == null) {
					setValue(null);
				}
				break;

			default:
				throw new HeaderDefinitionError("Invalid Dynamic function type "
						+ function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
						+ function.name().toLowerCase() + "' property. [@Field("
						+ function.name().toLowerCase()
						+ "=<string>) or @Dynamic(Property." + function.name() + ")]");
			}
		}

		/**
		 * Execute.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return the string
		 */
		public String execute(JHeader header, String name) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				if (isMapped) {
					return (String) method.invoke(header, name);
				} else {
					return (String) method.invoke(header);
				}

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		/**
		 * Sets the value.
		 * 
		 * @param value
		 *          the new value
		 */
		private void setValue(String value) {
			hasStaticValue = true;
			this.value = value;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.jnetpcap.packet.AnnotatedFieldMethod#StringMethod(org.jnetpcap.packet
		 * .JHeader)
		 */
		/**
		 * String method.
		 * 
		 * @param header
		 *          the header
		 * @param name
		 *          the name
		 * @return the string
		 * @see org.jnetpcap.packet.structure.AnnotatedFieldMethod#stringMethod(org.jnetpcap.packet.JHeader,
		 *      java.lang.String)
		 */
		@Override
		public String stringMethod(JHeader header, String name) {
			return execute(header, name);
		}
	}

	/**
	 * Check annotation.
	 * 
	 * @param method
	 *          the method
	 * @param fields
	 *          the fields
	 */
	public static void checkAnnotation(Method method, List<AnnotatedField> fields) {

		Dynamic runtime = method.getAnnotation(Dynamic.class);

		if (runtime.field().length() != 0) {

			boolean found = false;
			final String name = runtime.field();
			for (AnnotatedField f : fields) {
				if (f.getName().equals(name)) {
					found = true;
					break;
				}
			}

			if (!found) {
				throw new HeaderDefinitionError("field name defined in annotation ");
			}

		}
	}

	/**
	 * Check signature.
	 * 
	 * @param method
	 *          the method
	 * @param c
	 *          the c
	 */
	private static void checkSignature(Method method, Class<?> c) {
		final Class<?> declaringClass = method.getDeclaringClass();

		/*
		 * Now make sure it has the right signature of: <code>String name()</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if ((sig.length == 1 && sig[0] != String.class) || sig.length > 1
				|| method.getReturnType() != c) {
			throw new AnnotatedMethodException(declaringClass,
					"Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) != 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
					+ "()" + " can not be declared static");
		}
	}

	/**
	 * Generate function.
	 * 
	 * @param function
	 *          the function
	 * @param field
	 *          the field
	 * @return the annotated field method
	 */
	public static AnnotatedFieldMethod generateFunction(Field.Property function,
			AnnotatedField field) {

		switch (function) {
		case LENGTH:
		case OFFSET:
			return new IntFunction(field, function);

		case MASK:
			return new LongFunction(field, function);

		case VALUE:
			return new ObjectFunction(field, function);

		case CHECK:
			return new BooleanFunction(field, function);

		case UNITS:
		case DISPLAY:
		case DESCRIPTION:
			return new StringFunction(field, function);

		default:
			throw new HeaderDefinitionError("Unsupported Dynamic function type "
					+ function.toString());
		}

	}

	/**
	 * Guess field name.
	 * 
	 * @param name
	 *          the name
	 * @return the string
	 */
	private static String guessFieldName(String name) {
		if (name.startsWith("has")) {
			String cap = name.replace("has", "");
			char u = cap.charAt(0);
			char l = Character.toLowerCase(u);
			return cap.replace(u, l);
		} else if (name.endsWith("Description")) {
			return name.replace("Description", "");
		} else if (name.endsWith("Offset")) {
			return name.replace("Offset", "");
		} else if (name.endsWith("Length")) {
			return name.replace("Length", "");
		} else if (name.endsWith("Mask")) {
			return name.replace("Mask", "");
		} else if (name.endsWith("Value")) {
			return name.replace("Value", "");
		} else if (name.endsWith("Display")) {
			return name.replace("Display", "");
		} else if (name.endsWith("Units")) {
			return name.replace("Units", "");
		} else if (name.endsWith("Format")) {
			return name.replace("Format", "");
		} else {
			return name;
		}
	}

	/**
	 * Inspect method.
	 * 
	 * @param method
	 *          the method
	 * @return the annotated field method
	 */
	public static AnnotatedFieldMethod inspectMethod(Method method) {

		Dynamic runtime = method.getAnnotation(Dynamic.class);

		Field.Property function = runtime.value();
		switch (function) {
		case LENGTH:
		case OFFSET:
			checkSignature(method, int.class);
			return new IntFunction(method, function);

		case MASK:
			checkSignature(method, long.class);
			return new LongFunction(method, function);

		case VALUE:
			checkSignature(method, Object.class);

			return new ObjectFunction(method, function);

		case CHECK:
			checkSignature(method, boolean.class);
			return new BooleanFunction(method, function);

		case DISPLAY:
		case DESCRIPTION:
			checkSignature(method, String.class);
			return new StringFunction(method, function);

		default:
			throw new HeaderDefinitionError("Unsupported Dynamic function type "
					+ function.toString());
		}
	}

	/** The field. */
	protected final String field;

	/** The function. */
	protected final Field.Property function;

	/**
	 * Instantiates a new annotated field method.
	 * 
	 * @param field
	 *          the field
	 * @param function
	 *          the function
	 */
	public AnnotatedFieldMethod(AnnotatedField field, Field.Property function) {
		super();
		this.function = function;

		this.field = field.getName();
	}

	/**
	 * Instantiates a new annotated field method.
	 * 
	 * @param field
	 *          the field
	 * @param function
	 *          the function
	 * @param method
	 *          the method
	 */
	public AnnotatedFieldMethod(AnnotatedField field, Field.Property function,
			Method method) {
		super(method);
		this.function = function;

		this.field = field.getName();
	}

	/**
	 * Instantiates a new annotated field method.
	 * 
	 * @param method
	 *          the method
	 * @param function
	 *          the function
	 */
	public AnnotatedFieldMethod(Method method, Field.Property function) {
		super(method);
		this.function = function;

		Dynamic runtime = method.getAnnotation(Dynamic.class);
		if (runtime == null) {
			throw new HeaderDefinitionError(method.getDeclaringClass(),
					"unable get field's annotated runtime");
		}

		if (runtime.field().length() != 0) {
			this.field = runtime.field();
		} else {
			this.field = guessFieldName(method.getName());
		}
	}

	/**
	 * Boolean method.
	 * 
	 * @param header
	 *          the header
	 * @param name
	 *          the name
	 * @return true, if successful
	 */
	public boolean booleanMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
				"this return type is invalid for this function type");
	}

	/**
	 * Config from field.
	 * 
	 * @param field
	 *          the field
	 */
	public abstract void configFromField(AnnotatedField field);

	/**
	 * Gets the field name.
	 * 
	 * @return the field name
	 */
	public String getFieldName() {
		return field;
	}

	/**
	 * Gets the function.
	 * 
	 * @return the function
	 */
	public final Field.Property getFunction() {
		return this.function;
	}

	/**
	 * Int method.
	 * 
	 * @param header
	 *          the header
	 * @param name
	 *          the name
	 * @return the int
	 */
	public int intMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
				"this return type is invalid for this function type");
	}

	/**
	 * Object method.
	 * 
	 * @param header
	 *          the header
	 * @param name
	 *          the name
	 * @return the object
	 */
	public Object objectMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
				"this return type is invalid for this function type");
	}

	/**
	 * String method.
	 * 
	 * @param header
	 *          the header
	 * @param name
	 *          the name
	 * @return the string
	 */
	public String stringMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
				"this return type is invalid for this function type");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.AnnotatedMethod#validateSignature(java.lang.reflect
	 * .Method)
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
	}

	/**
	 * Long method.
	 * 
	 * @param header
	 *          the header
	 * @param name
	 *          the name
	 * @return the long
	 */
	public long longMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
				"this return type is invalid for this function type");
	}

}
