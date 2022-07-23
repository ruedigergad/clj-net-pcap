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
package org.jnetpcap.util.resolver;

import java.io.IOException;
import java.net.URL;

// TODO: Auto-generated Javadoc
/**
 * A resolver interface that can resolver various types of addresses and
 * specific protocol numbers and types to a human readable name. The resolver
 * will do an appropriate type of look up is appropriate for a given protocol,
 * to try and map a binary entity to a human assigned and readable one.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface Resolver {
	/**
	 * Type of resolver that can be registered with JRegistry. Resolvers job is to
	 * convert a binary number to a human readable name associated with it. For
	 * example IP resolver will convert ip address to hostnames.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum ResolverType {

		/** Converts MAC addresses to station names when defined. */
		IEEE_OUI_ADDRESS,

		/** Converts a MAC address manufacturer prefix to a name. */
		IEEE_OUI_PREFIX(new IEEEOuiPrefixResolver()),

		/** Converts Ip version 4 and 6 address to hostnames and constant labels. */
		IP(new IpResolver()),

		/** Converts TCP and UDP port numbers to application names. */
		PORT, ;

		/** The resolver. */
		private final Resolver resolver;

		/**
		 * Instantiates a new resolver type.
		 */
		private ResolverType() {
			this.resolver = null;
		}

		/**
		 * Instantiates a new resolver type.
		 * 
		 * @param resolver
		 *          the resolver
		 */
		private ResolverType(Resolver resolver) {
			this.resolver = resolver;
		}

		/**
		 * Gets the resolver.
		 * 
		 * @return the resolver
		 */
		public final Resolver getResolver() {
			return this.resolver;
		}
	}

	/** The Constant RESOLVER_SEARCH_PATH_PROPERTY. */
	public static final String RESOLVER_SEARCH_PATH_PROPERTY =
			"resolver.search.path";

	/**
	 * Checks if a mapping exists or can be made. This operation may trigger a
	 * lookup which may take certain amount of time to complete, some times many
	 * seconds or even minutes.
	 * 
	 * @param address
	 *          address to check mapping for
	 * @return true the mapping can be made, otherwise false
	 */
	public boolean canBeResolved(byte[] address);

	/**
	 * Resets the cache to its defaults.
	 */
	public void clearCache();

	/**
	 * This method is called everytime the resolver is requested from JRegistry.
	 * This method allows the resolver to initialize itself if it isn't already
	 * initialized.
	 */
	public void initializeIfNeeded();

	/**
	 * Checks if resolver already has a mapping made for this particular address.
	 * This operation does not block and returns immediately. The mapping may
	 * include a negative lookup, one that failed before. None the less the
	 * negative result is cached along with positive results.
	 * 
	 * @param address
	 *          address to check for
	 * @return true if mapping is already cached, otherwise false
	 */
	public boolean isCached(byte[] address);

	/**
	 * Attempts to load the cache from the given URL. The format of the file
	 * retrieved from the url is resolver specified. The default cache file format
	 * is attempted at some point in the file scan until the file can be read or
	 * the load fails.
	 * 
	 * @param url
	 *          URL of the resource containing the database to load
	 * @return number of entries cached
	 * @throws IOException
	 *           any IO errors
	 */
	public int loadCache(URL url) throws IOException;

	/**
	 * Attempts to resole an address to a human readable form. Any possible or
	 * required look ups are performed, sometimes taking a long time to complete
	 * if neccessary. All results, positive and negative for the lookup, are
	 * cached for certain amount of time. Defaults are
	 * 
	 * @param address
	 *          address to try and resolve
	 * @return human readable form if lookup succeeded (position) or null if
	 *         lookup failed to produce a human label.
	 */
	public String resolve(byte[] address);

	/**
	 * Forces cache contents to be saved to the default cache file.
	 * 
	 * @return number of cached entries saved
	 * @throws IOException
	 *           any IO errors during save
	 */
	public int saveCache() throws IOException;
}
