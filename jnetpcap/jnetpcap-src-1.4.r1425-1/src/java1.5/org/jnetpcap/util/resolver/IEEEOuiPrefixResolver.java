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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.logging.Level;

import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.util.JLogger;
import org.jnetpcap.util.config.JConfig;

// TODO: Auto-generated Javadoc
/**
 * A resolver that resolves the first 3 bytes of a MAC address to a manufacturer
 * code. The resolver loads jNetPcap supplied compressed oui database of
 * manufacturer codes and caches that information. The resolver can also
 * download over the internet, if requested, a raw IEEE OUI database of
 * manufacturer code, parse it and produce a cache file for future use.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class IEEEOuiPrefixResolver extends AbstractResolver {

	/**
	 * Default URI path to IEEE raw oui database of manufacturer codes. The URI is
	 * {@value #IEEE_OUI_DATABASE_PATH}.
	 */
	public final static String IEEE_OUI_DATABASE_PATH =
			"http://standards.ieee.org/regauth/oui/oui.txt";

	/** The Constant RESOURCE_COMPRESSED_OUI_DATABASE. */
	private static final String RESOURCE_COMPRESSED_OUI_DATABASE = "oui.txt";

	/** The Constant PROPERTY_OUI_DB_URL. */
	private static final String PROPERTY_OUI_DB_URL =
			"resolver.OUI_PREFIX.db.url";

	/** The Constant PROPERTY_OUI_DB_DOWNLOAD. */
	private static final String PROPERTY_OUI_DB_DOWNLOAD =
			"resolver.OUI_PREFIX.db.download";

	/** The Constant DEFAULT_OUI_DB_DOWNLOAD. */
	private static final String DEFAULT_OUI_DB_DOWNLOAD = "false";

	/** The initialized. */
	private boolean initialized = false;

	/**
	 * Creates an uninitalized Oui prefix resolver. The resolver is "late"
	 * initialized when its first called on to do work.
	 * 
	 */
	public IEEEOuiPrefixResolver() {
		super(JLogger.getLogger(IEEEOuiPrefixResolver.class), "OUI_PREFIX");
	}

	/**
	 * Initializes the resolver by first checking if there are any cached entries,
	 * if none, it reads the compressed oui database supplied with jNetPcap in the
	 * resource directory.
	 */
	@Override
	public void initializeIfNeeded() {
		if (initialized == false && hasCacheFile() == false) {
			initialized = true;

			setCacheCapacity(13000); // There are over 12,000 entries in the db

			super.initializeIfNeeded(); // Allow the baseclass to prep cache

			setPositiveTimeout(INFINITE_TIMEOUT); // Never
			setNegativeTimeout(0);

			/*
			 * First look for compressed OUI database.
			 */

			try {
				URL url = JConfig.getResourceURL(RESOURCE_COMPRESSED_OUI_DATABASE);
				if (url != null) {
					logger
							.fine("loading compressed database file from " + url.toString());
					readOuisFromCompressedIEEEDb(RESOURCE_COMPRESSED_OUI_DATABASE);
					return;
				}

				boolean download =
						Boolean.parseBoolean(JConfig.getProperty(PROPERTY_OUI_DB_DOWNLOAD,
								DEFAULT_OUI_DB_DOWNLOAD));
				String u = JConfig.getProperty(PROPERTY_OUI_DB_URL);
				if (u != null && download) {
					url = new URL(u);
					logger.fine("loading remote database " + url.toString());
					loadCache(url);
					return;
				}
			} catch (IOException e) {
				logger.log(Level.WARNING, "error while reading database", e);
			}
		} else {
			super.initializeIfNeeded();
		}
	}

	/**
	 * Download IEEE supplied OUI.txt database of manufacturer prefixes and codes.
	 * The file is downloaded using the protocol specified in the URL, parsed and
	 * cached indefinately. The machine making the URL connection must have
	 * internet connection available as well as neccessary security permissions
	 * form JRE in order to make the connection.
	 * <p>
	 * 
	 * @param url
	 *          The url of the IEEE resource to load. If the url is null, the
	 *          default uri is attempted {@value #IEEE_OUI_DATABASE_PATH}.
	 * @return number of entries cached
	 * @throws IOException
	 *           any IO errors
	 */
	@Override
	public int loadCache(URL url) throws IOException {
		if (url == null) {
			url = new URL(IEEE_OUI_DATABASE_PATH);
		}
		return readOuisFromRawIEEEDb(new BufferedReader(new InputStreamReader(
				url.openStream())));
	}

	/**
	 * Read ouis from compressed ieee db.
	 * 
	 * @param in
	 *          the in
	 * @return the int
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	private int readOuisFromCompressedIEEEDb(BufferedReader in)
			throws IOException {
		int count = 0;

		try {
			String s;
			while ((s = in.readLine()) != null) {
				String[] c = s.split(":", 2);
				if (c.length < 2) {
					continue;
				}

				Long i = Long.parseLong(c[0], 16);

				super.addToCache(i, c[1]);
				count++;

			}
		} finally {
			in.close(); // Make sure we close the file
		}

		return count;
	}

	/**
	 * Read ouis from compressed ieee db.
	 * 
	 * @param f
	 *          the f
	 * @return true, if successful
	 * @throws FileNotFoundException
	 *           the file not found exception
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	private boolean readOuisFromCompressedIEEEDb(String f)
			throws FileNotFoundException, IOException {
		/*
		 * Try local file first, more efficient
		 */
		File file = new File(f);
		if (file.canRead()) {
			readOuisFromCompressedIEEEDb(new BufferedReader(new FileReader(file)));
			return true;
		}

		/*
		 * Otherwise look for it in classpath
		 */
		InputStream in =
				JFormatter.class.getClassLoader().getResourceAsStream("resources/" + f);
		if (in == null) {
			return false; // Can't find it
		}
		readOuisFromCompressedIEEEDb(new BufferedReader(new InputStreamReader(in)));

		return true;
	}

	/**
	 * Read ouis from raw ieee db.
	 * 
	 * @param in
	 *          the in
	 * @return the int
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	private int readOuisFromRawIEEEDb(BufferedReader in) throws IOException {
		int count = 0;
		try {
			String s;
			while ((s = in.readLine()) != null) {
				if (s.contains("(base 16)")) {
					String[] c = s.split("\t\t");
					if (c.length < 2) {
						continue;
					}

					String id = c[0].split(" ")[0];
					long i = Long.parseLong(id, 16);
					String[] a = c[1].split(" ");

					if (a.length > 1) {
						String p = a[0]; // Prefix

						if (p.length() <= 3 || p.length() == 2 && p.charAt(1) == '.') {
							/* Too short, combine additional company name words */
							p += a[1]; // make it a little longer
						}

						/*
						 * Fix up the prefix and replace some invalid characters
						 */
						p = p.replace('.', '_');
						p = p.replace('-', '_');
						p = p.replace('\t', ' ').trim();
						p = p.replace(',', ' ').trim();

						if (p.endsWith("_") || p.endsWith("-")) {
							p = p.substring(0, p.length() - 1);
						}

						/*
						 * Transform some common long terms into short abbrieviations. Also
						 * transform their plural forms and upper and lower case
						 * counterpars.
						 */
						p = transform(p, a);

						/*
						 * Done, now cache it
						 */
						super.addToCache(i, p);
						count++;
					}
				}
			}
		} finally {
			in.close(); // Make sure we close the file
		}

		return count;
	}

	/**
	 * Transform.
	 * 
	 * @param str
	 *          the str
	 * @param a
	 *          the a
	 * @return the string
	 */
	private String transform(String str, String[] a) {
		int i = 1;
		while (true) {
			String more = (a.length > 1) ? a[i] : null;

			String after = transform(str, more);

			if (after == str) {
				break;
			}

			str = after;
		}

		return str;
	}

	/**
	 * Transform.
	 * 
	 * @param str
	 *          the str
	 * @param more
	 *          the more
	 * @return the string
	 */
	private String transform(String str, String more) {

		str = transform(str, more, "Graphic", "Graph");
		str = transform(str, more, "Electronic", "Elect");
		str = transform(str, more, "Application", "App");
		str = transform(str, more, "Incorporated", "Inc");
		str = transform(str, more, "Corporation", "Corp");
		str = transform(str, more, "Company", "Co");
		str = transform(str, more, "Technologies", "Tech");
		str = transform(str, more, "Technology", "Tech");
		str = transform(str, more, "Communication", "Com");
		str = transform(str, more, "Network", "Net");
		str = transform(str, more, "System", "Sys");
		str = transform(str, more, "Information", "Info");
		str = transform(str, more, "Industries", "Ind");
		str = transform(str, more, "Industrial", "Ind");
		str = transform(str, more, "Industry", "Ind");
		str = transform(str, more, "Laboratories", "Lab");
		str = transform(str, more, "Laboratory", "Ind");
		str = transform(str, more, "Enterprises", "Ent");
		str = transform(str, more, "Computer", "Cp");
		str = transform(str, more, "Manufacturing", "Mfg");
		str = transform(str, more, "Resources", "Res");
		str = transform(str, more, "Resource", "Res");
		str = transform(str, more, "Limited", "Ltd");
		str = transform(str, more, "International", "Int");
		str = transform(str, more, "Presentation", "Pres");
		str = transform(str, more, "Equipment", "Eq");
		str = transform(str, more, "Peripheral", "Pr");
		str = transform(str, more, "Interactive", "Int");

		return str;
	}

	/**
	 * Transform any reference to specific terms with abbrieviations. The method
	 * also makes the sigular form plural and checks both lower and upper case
	 * versions.
	 * 
	 * @param str
	 *          string to be transformed
	 * @param more
	 *          the more
	 * @param singular
	 *          term to look for in sigular form
	 * @param abbr
	 *          abbreviation to substitute in place
	 * @return new string
	 */
	private String transform(String str,
			String more,
			final String singular,
			final String abbr) {

		final String plural = singular + "s";

		str = str.replace(plural.toUpperCase(), abbr);
		str = str.replace(plural.toLowerCase(), abbr);
		str = str.replace(plural, abbr);

		str = str.replace(singular.toUpperCase(), abbr);
		str = str.replace(singular.toLowerCase(), abbr);
		str = str.replace(singular, abbr);

		/*
		 * If after transformation we end up just the short abbreviation, we need to
		 * add more to the string if we can from company parts.
		 */
		if (str.equals(abbr)) {
			if (more != null) {
				str += more;
			}
		}

		return str;
	}

	/**
	 * Resolves the supplied address to a human readable name.
	 * 
	 * @param address
	 *          the address
	 * @param hash
	 *          the hash
	 * @return resolved name or null if not resolved
	 */
	@Override
	public String resolveToName(byte[] address, long hash) {
		return null; // If its not in the cache, we don't know what it is
	}

	/**
	 * Generates a special hashcode for first 3 bytes of the address that is
	 * unique for every address.
	 * 
	 * @param address
	 *          the address
	 * @return the long
	 */
	@Override
	public long toHashCode(byte[] address) {
		return ((address[2] < 0) ? address[2] + 256 : address[2])
				| ((address[1] < 0) ? address[1] + 256 : address[1]) << 8
				| ((address[0] < 0) ? address[0] + 256 : address[0]) << 16;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.AbstractResolver#resolveToName(long, long)
	 */
	/**
	 * Resolve to name.
	 * 
	 * @param number
	 *          the number
	 * @param hash
	 *          the hash
	 * @return the string
	 * @see org.jnetpcap.util.resolver.AbstractResolver#resolveToName(long, long)
	 */
	@Override
	protected String resolveToName(long number, long hash) {
		throw new UnsupportedOperationException(
				"this resolver only resolves addresses in byte[] form");
	}
}
