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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.Pcap;

// TODO: Auto-generated Javadoc
/**
 * Native library management. This class verifies that native library was found
 * and loaded. Also checks if all the required symbols are present once a native
 * library is linked. This allows newer versions of the same library to contain
 * newer or enhanced API calls, which can be detected using this class.
 * 
 * @author Sly Technologies, Inc.
 */
@Library(natives = {
	"Kernel"
}, jni = Pcap.LIBRARY)
public class NativeLibrary {

	static {
		// try {
		// Class.forName(JNILibrary.class.getCanonicalName());
		// } catch (ClassNotFoundException e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// }
		//
		// JNILibrary.register(NativeLibrary.class);
		// JNILibrary.register(NativeLibraryReference.class);
	}

	private final static Map<String, NativeLibrary> cache =
			new HashMap<String, NativeLibrary>();

	/**
	 * Dlopen.
	 * 
	 * @param name
	 *            the name
	 * @return the long
	 */
	@LibraryMember
	native static long dlopen(String name);

	/**
	 * Method to actual load the library and post process more meaningful error
	 * messages if necessary.
	 * 
	 * @param name
	 *            native library (not extensions or directory paths)
	 * @param clazz
	 *            the clazz
	 * @param min
	 *            the min
	 * @return the library
	 */
	public static NativeLibrary loadLibrary(String name) {
		if (cache.containsKey(name)) {
			return cache.get(name);
		}

		NativeLibrary lib = new NativeLibrary(name);
		cache.put(name, lib);

		return lib;
	}

	/**
	 * Gets the native library handle.
	 * 
	 * @param name
	 *            the name
	 * @return the native library handle
	 */
	public static NativeLibrary open(String name) {
		return new NativeLibrary(name);
	}

	/** The address. */
	protected final long address;

	protected final List<Error> errors = new ArrayList<Error>();

	/**
	 * @return the errors
	 */
	public List<Error> getErrors() {
		return errors;
	}

	/** The name. */
	public final String name;

	/** The ref. */
	public final NativeLibraryReference ref;

	/**
	 * Instantiates a new native library.
	 * 
	 * @param name
	 *            the name
	 * @param error
	 */
	NativeLibrary(String name) {
		// final List<Error> errors = new ArrayList<Error>(1);

		this.address = dlopen(name);
		ref = (address != 0) ? new NativeLibraryReference(this, address) : null;

		this.name = name;
	}

	/**
	 * Instantiates a new native library with errors.
	 * 
	 * @param name
	 *            library name
	 * @param errors
	 *            existing errors
	 */
	NativeLibrary(String name, List<Error> errors) {
		// final List<Error> errors = new ArrayList<Error>(1);

		this.address = 0;
		this.errors.addAll(errors);
		ref = null;

		this.name = name;
	}

	/**
	 * Dlsymbol.
	 * 
	 * @param address
	 *            the address
	 * @param name
	 *            the name
	 * @return the long
	 */
	@LibraryMember
	native long dlsymbol(long address, String name);

	/**
	 * Dlsymbol.
	 * 
	 * @param name
	 *            the name
	 * @return the long
	 */
	long dlsymbol(String name) {
		return dlsymbol(address, name);
	}

	/**
	 * Gets the symbol.
	 * 
	 * @param name
	 *            the name
	 * @return the symbol
	 */
	public NativeSymbol getSymbol(String name) {
		if (symbols.containsKey(name)) {
			return symbols.get(name);
		}

		long address = dlsymbol(name);
		if (address == 0) {
			return null;
		}

		NativeSymbol symbol =
				new NativeSymbol(name, address,
						System.mapLibraryName(this.name));
		symbols.put(name, symbol);

		return symbol;
	}

	public static NativeSymbol cacheSymbolNegative(String name) {
		if (negativeSymbols.containsKey(name)) {
			return negativeSymbols.get(name);
		}

		NativeSymbol symbol = new NativeSymbol(name, 0, null);
		negativeSymbols.put(name, symbol);

		return symbol;
	}

	private final Map<String, NativeSymbol> symbols =
			new HashMap<String, NativeSymbol>();
	private final static Map<String, NativeSymbol> negativeSymbols =
			new HashMap<String, NativeSymbol>();

	public boolean isLoaded() {
		return address != 0L;
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

		b.append(name).append("@0x").append(Long.toString(address, 16));
		// b.append(Arrays.asList(symbols).toString());

		return b.toString();
	}

	/**
	 * @param string
	 * @return
	 */
	public static NativeSymbol findSymbol(String name) {
		for (NativeLibrary lib : cache.values()) {
			NativeSymbol sym = lib.getSymbol(name);
			if (sym != null) {
				return sym;
			}
		}

		return cacheSymbolNegative(name);
	}

}
