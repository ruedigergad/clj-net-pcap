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
package com.slytechs.library;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

// TODO: Auto-generated Javadoc
/**
 * Native library management. This class verifies that native library was found
 * and loaded. Also checks if all the required symbols are present once a native
 * library is linked. This allows newer versions of the same library to contain
 * newer or enhanced API calls, which can be detected using this class.
 * 
 * @author Sly Technologies, Inc.
 */
public class JNILibrary extends NativeLibrary {

	/** The Constant cache. */
	private final static Map<String, JNILibrary> cache =
			new HashMap<String, JNILibrary>();

	/**
	 * Filter all native methods.
	 * 
	 * @param declaredMethods
	 *            the declared methods
	 * @return the method[]
	 */
	private static Method[] filterAllNativeMethods(Method[] declaredMethods) {
		final List<Method> list = new LinkedList<Method>();

		for (Method m : declaredMethods) {
			if ((m.getModifiers() & Modifier.NATIVE) != 0) {
				list.add(m);
				m.setAccessible(true);
			}
		}

		return list.toArray(new Method[list.size()]);
	}

	/**
	 * Find annotated methods.
	 * 
	 * @param clazz
	 *            the clazz
	 * @param annotation
	 *            the annotation
	 * @return the method[]
	 */
	private static Method[] findAnnotatedMethods(Class<?> clazz,
			Class<LibraryInitializer> annotation) {

		List<Method> list = new LinkedList<Method>();

		for (Method method : clazz.getDeclaredMethods()) {
			if (method.isAnnotationPresent(annotation)) {
				list.add(method);
			}
		}

		return list.toArray(new Method[list.size()]);
	}

	public static JNISymbol findSymbol(Class<?> clazz, String methodName,
			Class<?>... parameterTypes) {
		try {
			return findSymbol(clazz.getMethod(methodName, parameterTypes));
		} catch (Exception e) {
			return JNISymbol.NOT_FOUND_SYMBOL;
		}
	}

	/**
	 * Find symbol.
	 * 
	 * @param m
	 *            the m
	 * @return the jNI symbol
	 */
	public static JNISymbol findSymbol(Method m) {
		for (JNILibrary lib : cache.values()) {
			JNISymbol sym = lib.getSymbol(m);
			if (sym != null) {
				return sym;
			}
		}

		return null;
	}

	public static String toStringAllLibraries() {
		StringBuilder b = new StringBuilder();
		for (JNILibrary lib : cache.values()) {
			b.append(lib.toString()).append("\n");
		}

		return b.toString();
	}

	/**
	 * Invoke static initializer on class.
	 * 
	 * @param clazz
	 *            the clazz
	 */
	private static void invokeStaticInitializerOnClass(Class<?> clazz) {

		Method[] inits = findAnnotatedMethods(clazz, LibraryInitializer.class);

		for (Method init : inits) {
			try {
				init.setAccessible(true); // Override security for private
											// methods
				init.invoke(null); // Its a static method
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

	/**
	 * Method to actual load the library and post process more meaningful error
	 * messages if necessary.
	 * 
	 * @param name
	 *            native library (not extensions or directory paths)
	 * @return the library
	 */
	public static JNILibrary loadLibrary(String name) {
		if (cache.containsKey(name)) {
			return cache.get(name);
		}

		List<Error> errors = new LinkedList<Error>();

		JNILibrary lib;
		if (loadLibrary(name, errors)) {
			lib = new JNILibrary(name);
		} else {
			lib = new JNILibrary(name, errors);
		}

		cache.put(name, lib);

		return lib;
	}

	/**
	 * Method to actual load the library and post process more meaningful error
	 * messages if necessary.
	 * 
	 * @param name
	 *            native library (not extensions or directory paths)
	 * @param errors
	 *            the errors
	 * @return the library
	 */
	public static boolean loadLibrary(String name, List<Error> errors) {

		Error error = null;

		try {
			System.loadLibrary(name);
		} catch (UnsatisfiedLinkError e) {
			error = e;
			String msg = e.getMessage();

			String mappedName = System.mapLibraryName(name);

			if (msg.contains("dependent libraries")) {
				error =
						new UnsatisfiedLinkError("missing depencies! ("
								+ mappedName + " is found)");
			}

			if (msg.contains("specified procedure")) {
				error =
						new UnsatisfiedLinkError(
								"Dependency version mismatch: "
										+ mappedName
										+ " library is found, but can't find a required native function"
										+ " call it is dependent on. Make sure all dependencies at the"
										+ " right version levels are installed.");
			}

			if (msg.contains("java.library.path")) {
				error =
						new UnsatisfiedLinkError(
								mappedName
										+ " native library is not found. "
										+ "Make sure its installed in /usr/lib or /usr/lib64 or "
										+ "\\windows\\system32 or \\widows\\system64 or "
										+ "set JVM -Djava.library.path=<dir_path_jnetpcap_library> to "
										+ "its location.");
			}

		} catch (Error e) {
			error = e;

		}

		if (error != null) {
			errors.add(error);
		}

		return error == null;
	}

	/**
	 * Open.
	 * 
	 * @param name
	 *            the name
	 * @return the jNI library
	 */
	public static JNILibrary open(String name) {
		return JNILibrary.loadLibrary(name);
	}

	/**
	 * Register.
	 * 
	 * @param clazz
	 *            the clazz
	 */
	public static void register(Class<?> clazz) {
		Library annotatedLibrary = clazz.getAnnotation(Library.class);
		if (annotatedLibrary != null) {
			register(annotatedLibrary);
			registerNativeMethods(annotatedLibrary.defaultAPI(),
					clazz.getDeclaredMethods());
		} else {
			registerNativeMethods(Library.API, clazz.getDeclaredMethods());
		}

		invokeStaticInitializerOnClass(clazz);
	}

	/**
	 * Register.
	 * 
	 * @param annotatedLibrary
	 *            the annotated library
	 */
	public static void register(Library annotatedLibrary) {
		register(annotatedLibrary.natives(),
				annotatedLibrary.jni(),
				annotatedLibrary.preload());
	}

	/**
	 * Register.
	 * 
	 * @param natives
	 *            the natives
	 * @param jni
	 *            the jni
	 * @param preload
	 *            the preload
	 */
	public static void register(String[] natives, String[] jni,
			Class<?>[] preload) {

		/*
		 * Load JNI libraries. These libraries have definitions for our class
		 * methods marked with native modifier. JNI libraries are loaded using
		 * System.loadLibrary() call.
		 */
		for (String name : jni) {
			JNILibrary lib = JNILibrary.loadLibrary(name);
			if (!lib.isLoaded()) {
				throw new UnsatisfiedLinkError(lib.errors.toString());
			}
		}

		/*
		 * Load 3rd party, external native raw libraries. These libraries are
		 * opened using dlopen call, and not loaded like JNI libraries. They are
		 * typically loaded as a dependency to one of the JNI libraries, but not
		 * necessarily. Any native library can be opened this way.
		 */
		for (String name : natives) {
			NativeLibrary.loadLibrary(name);
		}

		/*
		 * Pre-load a list of classes. This forces each class to be loaded and
		 * initialized. It also allows each of those classes to register
		 * themselves and initialize their own libraries.
		 */
		for (Class<?> clazz : preload) {
			try {
				Class.forName(clazz.getCanonicalName());
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Register native methods.
	 * 
	 * @param defaultApi
	 *            the default api
	 * @param methods
	 *            the methods
	 * @return true, if successful
	 */
	public static boolean registerNativeMethods(String defaultApi,
			Method[] methods) {
		methods = filterAllNativeMethods(methods);

		for (Method method : methods) {
			JNILibrary.findSymbol(method);
		}

		return true;
	}

	/**
	 * Resolve symbols.
	 * 
	 * @param clazz
	 *            the clazz
	 * @return true, if successful
	 */
	public static boolean resolveSymbols(Class<?> clazz) {
		Method[] natives = filterAllNativeMethods(clazz.getDeclaredMethods());

		boolean requiredSymbolsFound = true;
		for (Method m : natives) {
			JNISymbol sym = findSymbol(m);
			if (sym == null) {
				requiredSymbolsFound = false;
			} else {
				sym.register();
			}
		}

		return requiredSymbolsFound;
	}

	/**
	 * @return
	 */
	public static String toStringClassSymbols(Class<?>... clazzes) {
		StringBuilder out = new StringBuilder();
		StringBuilder b = new StringBuilder();

		for (JNILibrary lib : cache.values()) {
			boolean hadSymbol = false;
			b.setLength(0);
			b.append(lib.name).append("@0x")
					.append(Long.toString(lib.address, 16));

			b.append('[');
			int div = b.length();

			for (JNISymbol symbol : lib.symbols.values()) {
				boolean gotit = false;
				for (Class<?> clazz : clazzes) {
					if (symbol.clazz == clazz) {
						gotit = true;
						break;
					}
				}
				if (!gotit) {
					continue;
				}

				hadSymbol = true;

				b.append((b.length() != div) ? "\n " : "\n ");
				b.append(symbol.toString());
			}

			b.append((b.length() != div) ? "\n" : "");
			b.append("]\n");

			if (hadSymbol) {
				out.append(b);
			}
		}
		return out.toString();
	}

	/** The dependencies loaded. */
	private final boolean dependenciesLoaded = true;

	/** The symbols. */
	private final Map<String, JNISymbol> symbols =
			new HashMap<String, JNISymbol>();

	/**
	 * Instantiates a new jNI library.
	 * 
	 * @param name
	 *            the name
	 */
	private JNILibrary(String name) {
		super(name);
	}

	/**
	 * Instantiates a new jNI library.
	 * 
	 * @param name
	 *            the name
	 * @param errors
	 *            the errors
	 */
	private JNILibrary(String name, List<Error> errors) {
		super(name, errors);
	}

	/**
	 * Gets the symbol.
	 * 
	 * @param method
	 *            the method
	 * @return the symbol
	 * @throws SecurityException
	 *             the security exception
	 */
	JNISymbol getSymbol(Method method) throws SecurityException {

		final String jniNameShort = JNISymbol.toJNIName(method);
		final String jniNameAndSignature =
				JNISymbol.toJNINameAndSignature(method);
		// System.out.printf("getSymbol() - %s%n", jniNameAndSignature);

		if (symbols.containsKey(jniNameShort)) {
			return symbols.get(jniNameShort);
		}

		if (symbols.containsKey(jniNameAndSignature)) {
			return symbols.get(jniNameAndSignature);
		}

		String jniName = jniNameShort;
		long address = dlsymbol(jniName);
		if (address == 0) {
			address = dlsymbol(jniName = jniNameAndSignature);
			if (address == 0) {
				return null;
			}
		}

		JNISymbol symbol = new JNISymbol(jniName, address, method, this.name);
		symbols.put(jniName, symbol);

		return symbol;
	}

	/**
	 * Checks the load status of this library, including status of the required
	 * dependencies. Optional dependencies, even when failed to load, are not
	 * reported by this method.
	 * 
	 * @return true means library and its reuired dependencies loaded
	 *         successfully
	 * @see com.slytechs.library.NativeLibrary#isLoaded()
	 */
	@Override
	public boolean isLoaded() {
		return super.isLoaded() && dependenciesLoaded;
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder b = new StringBuilder();

		b.append(super.name).append("@0x").append(Long.toString(address, 16));

		if (!symbols.isEmpty()) {
			b.append('[');
			b.append(symbols.size()).append(" symbols");
			int div = b.length();
			for (JNISymbol symbol : symbols.values()) {
				b.append((b.length() != div) ? "\n " : "\n ");
				b.append(symbol.toString());
			}

			b.append((b.length() != div) ? "\n" : "");
			b.append(']');
		}

		return b.toString();
	}

	/**
	 * @return
	 */
	public String toStringNotLoaded() {
		StringBuilder b = new StringBuilder();

		b.append(super.name).append("@0x").append(Long.toString(address, 16));

		if (!symbols.isEmpty()) {
			b.append('[');
			int div = b.length();
			for (JNISymbol symbol : symbols.values()) {
				if (symbol.isLoaded()) {
					continue;
				}

				b.append((b.length() != div) ? "\n " : "\n ");
				b.append(symbol.toString());
			}

			b.append((b.length() != div) ? "\n" : "");
			b.append(']');
		}

		return b.toString();
	}
}
