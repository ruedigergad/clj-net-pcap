/**
 * 
 */
package com.slytechs.library;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * @author markbe
 * 
 */
public class JNIFormat {

	public static String mangleClassPath(Class<?> c) {
		return c.getCanonicalName().replace('.', '_');
	}

	public static String mangleClassSig(Class<?> c) {
		return c.getCanonicalName().replace('.', '/');
	}

	public static String mangleTypes(Class<?>[] types) {
		StringBuilder b = new StringBuilder();

		for (Class<?> t : types) {
			b.append(jniType(t));
		}

		return b.toString();
	}

	public static String jniParenSignature(Method method) {
		StringBuilder b = new StringBuilder();

		b.append("(");

		for (Class<?> t : method.getParameterTypes()) {
			b.append(jniType(t));
		}

		b.append(")");
		b.append(jniType(method.getReturnType()));

		return b.toString();
	}

	public static String jniSignature(Method method) {
		StringBuilder b = new StringBuilder();

		for (Class<?> t : method.getParameterTypes()) {
			b.append(jniType(t));
		}

		return b.toString();
	}

	public static String jniMethodName(Class<?> clazz, String m) {
		final StringBuilder b = new StringBuilder();

		b.append("Java_");
		b.append(mangleClassPath(clazz));
		b.append("_");
		b.append(m);

		return b.toString();
	}

	public static String jniMethodName(Method m) {
		final StringBuilder b = new StringBuilder();
		final Class<?> clazz = m.getDeclaringClass();

		b.append("Java_");
		b.append(mangleClassPath(clazz));
		b.append("_");
		b.append(m.getName());

		return b.toString();
	}

	public static String jniMethodNameAndSignature(Method m) {
		final StringBuilder b = new StringBuilder();
		final Class<?> clazz = m.getDeclaringClass();

		b.append("Java_");
		b.append(mangle(clazz.getCanonicalName()));
		b.append("_");
		b.append(mangle(m.getName()));
		b.append("__");
		b.append(mangle(jniSignature(m)));

		return b.toString();
	}

	public static String mangle(String original) {
		String mangled = original;

		mangled = mangled.replaceAll("_", "_1");
		mangled = mangled.replaceAll(";", "_2");
		mangled = mangled.replaceAll("\\[", "_3");
		mangled = mangled.replaceAll("\\.", "_");
		mangled = mangled.replaceAll("/", "_");

		return mangled;
	}

	public static String jniType(Class<?> c) {
		if (c.isPrimitive()) {
			if (c == void.class) {
				return "V";
			} else if (c == boolean.class) {
				return "Z";
			} else if (c == byte.class) {
				return "B";
			} else if (c == char.class) {
				return "C";
			} else if (c == short.class) {
				return "S";
			} else if (c == int.class) {
				return "I";
			} else if (c == long.class) {
				return "J";
			} else if (c == float.class) {
				return "F";
			} else if (c == double.class) {
				return "D";
			}
		}

		if (c.isArray()) {
			final Class<?> ctype = c.getComponentType();
			return "[" + jniType(ctype);
		}

		return "L" + c.getCanonicalName().replace('.', '/') + ";";

	}

	/**
	 * @param parameterTypes
	 * @return
	 */
	public static String javaParameters(Class<?>... parameterTypes) {
		StringBuilder b = new StringBuilder();

		b.append('(');
		b.append(javaTypes(parameterTypes));
		b.append(')');

		return b.toString();
	}

	public static String javaTypes(Class<?>... parameterTypes) {
		StringBuilder b = new StringBuilder();

		for (Class<?> pt : parameterTypes) {
			if (b.length() > 1) {
				b.append(", ");
			}
			b.append(pt.getSimpleName());
		}

		return b.toString();

	}

	public static String javaModifiers(int modifiers) {
		return Modifier.toString(modifiers);
	}

	public static String javaModifiers(Method m) {
		return Modifier.toString(m.getModifiers());
	}

	public static String javaModifiers(Field f) {
		return Modifier.toString(f.getModifiers());
	}

	public static String javaModifiers(Class<?> c) {
		return Modifier.toString(c.getModifiers());
	}

	/**
	 * @param clazz
	 * @return
	 */
	public static String jType(Class<?> c) {
		if (c.isPrimitive()) {
			if (c == void.class) {
				return "void";
			} else if (c == boolean.class) {
				return "jboolean";
			} else if (c == byte.class) {
				return "jbyte";
			} else if (c == char.class) {
				return "jchar";
			} else if (c == short.class) {
				return "jshort";
			} else if (c == int.class) {
				return "jint";
			} else if (c == long.class) {
				return "jlong";
			} else if (c == float.class) {
				return "jfloat";
			} else if (c == double.class) {
				return "jdouble";
			}
		}

		if (c == String.class) {
			return "jstring";
		}

		if (c == Class.class) {
			return "jclass";
		}

		if (c.isArray()) {
			return "jarray";
		}

		return "jobject";
	}
}
