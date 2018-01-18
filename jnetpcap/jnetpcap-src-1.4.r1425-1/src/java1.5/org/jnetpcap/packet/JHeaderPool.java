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
package org.jnetpcap.packet;

import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * A thread local pool of instances of headers. The header pool keeps track of
 * instances of headers it allocates based on protocol and thread IDs. The class
 * allows private pools and also provides a global singleton pool which can be
 * referenced from anywhere.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unchecked")
public class JHeaderPool {

	/** The local. */
	private static JHeaderPool local = new JHeaderPool();

	/** The locals. */
	private ThreadLocal<? extends JHeader>[] locals =
	    new ThreadLocal[JRegistry.MAX_ID_COUNT];

	/**
	 * Gets an instance of a header for the given ID type. The headers are
	 * allocated on a per thread basis. Eath thread uses its own pool of instance
	 * headers. A call with the same ID and within the same thread will return the
	 * same exact instance of a header that was returned from a previous call
	 * using the same ID and thread.
	 * 
	 * @param id
	 *          numerical ID of the protocol header as assigned by JRegistry
	 * @return a shared instance of a header per thread per ID
	 * @throws UnregisteredHeaderException
	 *           thrown if ID is invalid
	 */
	public JHeader getHeader(int id) throws UnregisteredHeaderException {
		return getHeader(JRegistry.lookupClass(id), id);
	}

	/**
	 * Gets an instance of a header for the protocol constant. The headers are
	 * allocated on a per thread basis. Eath thread uses its own pool of instance
	 * headers. A call with the same ID and within the same thread will return the
	 * same exact instance of a header that was returned from a previous call
	 * using the same ID and thread.
	 * <p>
	 * This method does not throw an exception since all core protocols are always
	 * registered and always accessible.
	 * </p>
	 * 
	 * @param <T>
	 *          the generic type
	 * @param protocol
	 *          core protocol constant
	 * @return a shared instance of a header per thread per ID
	 */
	public <T extends JHeader> T getHeader(JProtocol protocol) {
		return (T) getHeader(protocol.getHeaderClass(), protocol.getId());
	}

	/**
	 * Gets an instance of a header for the given ID type. The headers are
	 * allocated on a per thread basis. Eath thread uses its own pool of instance
	 * headers. A call with the same ID and within the same thread will return the
	 * same exact instance of a header that was returned from a previous call
	 * using the same ID and thread.
	 * 
	 * @param <T>
	 *          header class name
	 * @param clazz
	 *          parameterized class name that the retrieved header instance will
	 *          be cast to
	 * @param id
	 *          numerical ID of the protocol header as assigned by JRegistry
	 * @return a shared instance of a header per thread per ID
	 */
	public <T extends JHeader> T getHeader(final Class<T> clazz, int id) {

		ThreadLocal<T> local = (ThreadLocal<T>) locals[id];
		if (local == null) {
			local = new ThreadLocal<T>() {

				@Override
				protected T initialValue() {
					try {
						return clazz.newInstance();
					} catch (Exception e) {
						throw new IllegalStateException(e);
					}
				}
			};

			locals[id] = local;
		}

		return local.get();
	}

	/**
	 * Gets a default global instance of this header pool.
	 * 
	 * @return the default
	 */
	public static JHeaderPool getDefault() {
		return local;
	}

}
