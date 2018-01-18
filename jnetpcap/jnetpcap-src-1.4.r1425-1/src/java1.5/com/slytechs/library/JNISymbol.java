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
import java.util.LinkedList;
import java.util.List;


// TODO: Auto-generated Javadoc
/**
 * A symbol that is part of a library.
 * 
 * @author Sly Technologies, Inc.
 * 
 */
public class JNISymbol extends NativeSymbol {

	static final JNISymbol NOT_FOUND_SYMBOL;

	static {
		JNISymbol s = null;
		try {
			Method method = Class.class.getMethod("forName", String.class);
			s = new JNISymbol("", 0, method, "");
		} catch (Exception e) {
			e.printStackTrace();
		}
		NOT_FOUND_SYMBOL = s;
	}

	native static void registerSymbol(Class<?> clazz,
			long address,
			String name,
			String signature);

	/**
	 * To jni name.
	 * 
	 * @param method
	 *          the method
	 * @return the string
	 */
	public static String toJNIName(Method method) {
		return JNIFormat.jniMethodName(method);
	}

	public static String toJNINameAndSignature(Method method) {
		return JNIFormat.jniMethodNameAndSignature(method);
	}

	/**
	 * To jni signature.
	 * 
	 * @param method
	 *          the method
	 * @return the string
	 */
	public static String toJNISignature(Method method) {
		return JNIFormat.jniParenSignature(method);
	}

	/** The clazz. */
	public final Class<?> clazz;

	/** The java name. */
	public final String javaName;

	/** The jni signature. */
	public final String jniSignature;

	/** The method. */
	public final Method method;

	public final boolean foundAllSymbols;

	public final NativeSymbol[] natives;

	/**
	 * Instantiates a new symbol.
	 * 
	 * @param jniName
	 *          the jni name
	 * @param address
	 *          the address
	 * @param method
	 *          the method
	 * @param libName
	 */
	JNISymbol(String jniName, long address, Method method, String libName) {
		super(jniName, address, System.mapLibraryName(libName));

		this.clazz = method.getDeclaringClass();
		this.method = method;
		this.javaName = method.getName();
		this.jniSignature = JNIFormat.jniParenSignature(method);

		List<NativeSymbol> list = new LinkedList<NativeSymbol>();
		LibraryMember member = method.getAnnotation(LibraryMember.class);
		boolean symbolsFound = true;
		if (member != null) {
			for (String symbol : member.value()) {
				NativeSymbol n = NativeLibrary.findSymbol(symbol);
				if (!n.isFound() && symbolsFound) {
					symbolsFound = false;
				}
				list.add(n);
			}
		}
		this.natives = list.toArray(new NativeSymbol[list.size()]);

		this.foundAllSymbols = symbolsFound;
	}

	public void register() {
		// Rely on automatic java JNI registration mechanism
	}

	public boolean isLoaded() {
		return address != 0 && foundAllSymbols;
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		final StringBuilder b = new StringBuilder();

		b.append(libName).append("::").append(nativeName);

		if (method != null) {
			b.append(nativeName.contains("__") == false ? jniSignature : "(...)");
		}

		b.append("@0x").append(Long.toString(address, 16));
		if (natives.length != 0) {
			b.append("[");
			int div = b.length();
			for (NativeSymbol s : natives) {
				b.append((b.length() != div) ? ", " : "");
				b.append(s.toString());
			}
			b.append("]");
		}

		return b.toString();
	}
}
