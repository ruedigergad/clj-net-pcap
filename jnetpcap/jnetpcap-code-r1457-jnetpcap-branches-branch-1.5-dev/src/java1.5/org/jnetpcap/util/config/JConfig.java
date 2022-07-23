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
package org.jnetpcap.util.config;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.InvalidPropertiesFormatException;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jnetpcap.util.JLogger;

// TODO: Auto-generated Javadoc
/**
 * JConfig is responsible for jNetPcap configuration and global environment
 * maintentance. Its main purpose to locate resources such as config files, read
 * system properties and create an environment where resolver files can be
 * stored and maintained. The class provides various static (global) methods for
 * this purpose.
 * <p>
 * Property names and constant values:
 * <ul>
 * <li>{@value #CACHE_DIR_PROPERTY} - property defines full directory name
 * where resolver files are saved
 * <li>{@value #CACHE_FILE_SUFFIX_PROPERTY} - property defines overrides the
 * default suffix name (default value {@value #CACHE_FILE_SUFFIX})
 * <li>{@value #CACHE_SUB_DIR_PROPERTY} property overrides the default sub
 * directory name used, if explicit full directory is not defined (default value
 * {@value #CACHE_SUB_DIR})
 * <li>{@value #USER_HOME_PROPERTY} - system property which defines where the
 * current user's home dir is
 * </ul>
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JConfig {

	/**
	 * The Class ClasspathSearch.
	 */
	protected static class ClasspathSearch implements SearchPath {

		/** The resource. */
		private final ConfigString resource;

		/**
		 * Instantiates a new classpath search.
		 * 
		 * @param resource
		 *          the resource
		 */
		public ClasspathSearch(ConfigString resource) {
			this.resource = resource;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		/**
		 * Gets the file.
		 * 
		 * @param name
		 *          the name
		 * @return the file
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getFile(java.lang.String)
		 */
		public File getFile(String name) throws IOException {
			return null;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.JConfig.SearchPath#get(java.lang.String)
		 */
		/**
		 * Gets the input stream.
		 * 
		 * @param name
		 *          the name
		 * @return the input stream
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getInputStream(java.lang.String)
		 */
		public InputStream getInputStream(String name) throws IOException {
			URL url = getURL(name);

			return (url == null) ? null : url.openStream();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.JConfig.SearchPath#getURL(java.lang.String)
		 */
		/**
		 * Gets the uRL.
		 * 
		 * @param name
		 *          the name
		 * @return the uRL
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getURL(java.lang.String)
		 */
		public URL getURL(String name) throws IOException {
			resource.reset();

			if (resource.expand(name, globalVariables, topReadOnlyProperties)) {
				final String s = resource.toString();
				URL in = JConfig.class.getClassLoader().getResource(s);
				if (in != null) {
					logger.log(Level.FINER, "CLASSPATH: found " + s);
				} else {
					logger.log(Level.FINEST, "CLASSPATH: not found " + s);
				}

				return in;
			} else {

				logger.log(Level.FINEST, "CLASSPATH: failed to expand "
				    + resource.toString());
				return null;
			}
		}

		/**
		 * To string.
		 * 
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		public String toString() {
			return "Classpath(" + resource.getTemplate() + ")";
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		/**
		 * Gets the dir.
		 * 
		 * @param name
		 *          the name
		 * @return the dir
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		public File getDir(String name) {
			return null;
		}
	}

	/**
	 * The Class CompositeProperties.
	 */
	private static class CompositeProperties
	    extends Properties {

		/** The Constant serialVersionUID. */
		private static final long serialVersionUID = 98826036967593082L;

		/** The properties. */
		private Properties[] properties;

		/** The save. */
		private Properties save = null;

		/**
		 * Instantiates a new composite properties.
		 * 
		 * @param properties
		 *          the properties
		 */
		public CompositeProperties(Properties... properties) {
			this.properties = properties;
		}

		/**
		 * Adds the properties.
		 * 
		 * @param properties
		 *          the properties
		 */
		public void addProperties(Properties... properties) {
			this.properties = properties;
		}

		/**
		 * Contains.
		 * 
		 * @param value
		 *          the value
		 * @return true, if successful
		 * @see java.util.Hashtable#contains(java.lang.Object)
		 */
		@Override
		public synchronized boolean contains(Object value) {
			for (Properties p : properties) {
				if (p.contains(value)) {
					return true;
				}
			}

			return false;
		}

		/**
		 * Contains key.
		 * 
		 * @param key
		 *          the key
		 * @return true, if successful
		 * @see java.util.Hashtable#containsKey(java.lang.Object)
		 */
		@Override
		public synchronized boolean containsKey(Object key) {
			for (Properties p : properties) {
				if (p.containsKey(key)) {
					return true;
				}
			}

			return false;
		}

		/**
		 * Flatten.
		 * 
		 * @return the properties
		 */
		private Properties flatten() {
			Properties flat = new Properties();

			for (int i = properties.length - 1; i >= 0; i--) {
				Properties p = properties[i];
				flat.putAll(p);
			}

			return flat;
		}

		/**
		 * Gets the property.
		 * 
		 * @param key
		 *          the key
		 * @return the property
		 * @see java.util.Properties#getProperty(java.lang.String)
		 */
		@Override
		public String getProperty(String key) {
			return getProperty(key, null);
		}

		/**
		 * Gets the property.
		 * 
		 * @param key
		 *          the key
		 * @param defaultValue
		 *          the default value
		 * @return the property
		 * @see java.util.Properties#getProperty(java.lang.String, java.lang.String)
		 */
		@Override
		public String getProperty(String key, String defaultValue) {
			for (Properties p : properties) {
				if (p.containsKey(key)) {
					return p.getProperty(key);
				}
			}

			if (defaultValue == null) {
				return null;
			}

			return defaultValue;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Hashtable#keySet()
		 */
		/**
		 * Key set.
		 * 
		 * @return the sets the
		 * @see java.util.Hashtable#keySet()
		 */
		@Override
		public Set<Object> keySet() {
			return flatten().keySet();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#list(java.io.PrintStream)
		 */
		/**
		 * List.
		 * 
		 * @param out
		 *          the out
		 * @see java.util.Properties#list(java.io.PrintStream)
		 */
		@Override
		public void list(PrintStream out) {
			flatten().list(out);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#list(java.io.PrintWriter)
		 */
		/**
		 * List.
		 * 
		 * @param out
		 *          the out
		 * @see java.util.Properties#list(java.io.PrintWriter)
		 */
		@Override
		public void list(PrintWriter out) {
			flatten().list(out);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#load(java.io.InputStream)
		 */
		/**
		 * Load.
		 * 
		 * @param inStream
		 *          the in stream
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see java.util.Properties#load(java.io.InputStream)
		 */
		@Override
		public synchronized void load(InputStream inStream) throws IOException {
			throw new UnsupportedOperationException("invalid operation in composite");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#loadFromXML(java.io.InputStream)
		 */
		/**
		 * Load from xml.
		 * 
		 * @param in
		 *          the in
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @throws InvalidPropertiesFormatException
		 *           the invalid properties format exception
		 * @see java.util.Properties#loadFromXML(java.io.InputStream)
		 */
		@Override
		public synchronized void loadFromXML(InputStream in) throws IOException,
		    InvalidPropertiesFormatException {
			throw new UnsupportedOperationException("invalid operation in composite");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#propertyNames()
		 */
		/**
		 * Property names.
		 * 
		 * @return the enumeration
		 * @see java.util.Properties#propertyNames()
		 */
		@Override
		public Enumeration<?> propertyNames() {
			return flatten().propertyNames();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#setProperty(java.lang.String, java.lang.String)
		 */
		/**
		 * Sets the property.
		 * 
		 * @param key
		 *          the key
		 * @param value
		 *          the value
		 * @return the object
		 * @see java.util.Properties#setProperty(java.lang.String, java.lang.String)
		 */
		@Override
		public synchronized Object setProperty(String key, String value) {
			if (save != null) {
				return save.setProperty(key, value);
			}

			return null;
		}

		/**
		 * Sets the save properties.
		 * 
		 * @param userProperties
		 *          the new save properties
		 */
		public void setSaveProperties(Properties userProperties) {
			this.save = userProperties;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#store(java.io.OutputStream, java.lang.String)
		 */
		/**
		 * Store.
		 * 
		 * @param out
		 *          the out
		 * @param comments
		 *          the comments
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see java.util.Properties#store(java.io.OutputStream, java.lang.String)
		 */
		@Override
		public synchronized void store(OutputStream out, String comments)
		    throws IOException {
			for (Properties p : properties) {
				p.store(out, comments);
				out.flush();
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#storeToXML(java.io.OutputStream,
		 *      java.lang.String)
		 */
		/**
		 * Store to xml.
		 * 
		 * @param os
		 *          the os
		 * @param comment
		 *          the comment
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see java.util.Properties#storeToXML(java.io.OutputStream,
		 *      java.lang.String)
		 */
		@Override
		public synchronized void storeToXML(OutputStream os, String comment)
		    throws IOException {
			flatten().storeToXML(os, comment);
			os.flush();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Properties#storeToXML(java.io.OutputStream,
		 *      java.lang.String, java.lang.String)
		 */
		/**
		 * Store to xml.
		 * 
		 * @param os
		 *          the os
		 * @param comment
		 *          the comment
		 * @param encoding
		 *          the encoding
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see java.util.Properties#storeToXML(java.io.OutputStream,
		 *      java.lang.String, java.lang.String)
		 */
		@Override
		public synchronized void storeToXML(
		    OutputStream os,
		    String comment,
		    String encoding) throws IOException {

			flatten().storeToXML(os, comment, encoding);
			os.flush();
		}

	}

	/**
	 * The Class FilesystemSearch.
	 */
	protected static class FilesystemSearch implements SearchPath {
		
		/** The filename. */
		private final ConfigString filename;

		/**
		 * Instantiates a new filesystem search.
		 * 
		 * @param filename
		 *          the filename
		 */
		public FilesystemSearch(ConfigString filename) {
			this.filename = filename;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		/**
		 * Gets the file.
		 * 
		 * @param name
		 *          the name
		 * @return the file
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getFile(java.lang.String)
		 */
		public File getFile(String name) throws IOException {
			filename.reset();

			if (filename.expand(name, globalVariables, topReadOnlyProperties)) {
				final String s = filename.toString();

				File file = new File(s);
				if (file.isFile()) {
					logger.log(Level.FINER, "FILE: found " + s);
					return file;
				}

				logger.log(Level.FINEST, "FILE: not found " + s);
			} else {
				logger.log(Level.FINEST, "FILE: failed to expand "
				    + filename.toString());
			}

			return null;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.JConfig.SearchPath#get(java.lang.String)
		 */
		/**
		 * Gets the input stream.
		 * 
		 * @param name
		 *          the name
		 * @return the input stream
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getInputStream(java.lang.String)
		 */
		public InputStream getInputStream(String name) throws IOException {
			File file = getFile(name);
			if (file != null) {
				return new FileInputStream(file);
			} else {
				return null;
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.JConfig.SearchPath#get(java.lang.String)
		 */
		/**
		 * Gets the uRL.
		 * 
		 * @param name
		 *          the name
		 * @return the uRL
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getURL(java.lang.String)
		 */
		public URL getURL(String name) throws IOException {
			File file = getFile(name);
			if (file != null) {
				return file.toURI().toURL();
			} else {
				return null;
			}
		}

		/**
		 * To string.
		 * 
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		public String toString() {
			return "File(" + filename.getTemplate() + ")";
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		/**
		 * Gets the dir.
		 * 
		 * @param name
		 *          the name
		 * @return the dir
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		public File getDir(String name) {
			filename.reset();

			if (filename.expand(name, globalVariables, topReadOnlyProperties)) {
				final String s = filename.toString();

				File file = new File(s);
				if (file.isDirectory()) {
					logger.log(Level.FINER, "FILE: found " + s);
					return file;
				}

				logger.log(Level.FINEST, "FILE: not found " + s);
			} else {
				logger.log(Level.FINEST, "FILE: failed to expand "
				    + filename.toString());
			}

			return null;
		}

	}

	/**
	 * The Class PreprocessStream.
	 */
	private static class PreprocessStream
	    extends InputStream {

		/** The Constant str. */
		private final static byte[] str = {
		    '\\',
		    '\r',
		    '\n' };

		/** The in. */
		private final BufferedInputStream in;

		/**
		 * Instantiates a new preprocess stream.
		 * 
		 * @param in
		 *          the in
		 */
		public PreprocessStream(InputStream in) {
			this.in = new BufferedInputStream(in, 3);
		}

		/**
		 * Match reamining chars.
		 * 
		 * @return true, if successful
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 */
		private boolean matchReaminingChars() throws IOException {
			in.mark(2);

			if (in.read() != str[1]) {
				in.reset();
				return false;
			}

			if (in.read() != str[2]) {
				in.reset();
				return false;
			}

			return true;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.BufferedInputStream#read()
		 */
		/**
		 * Read.
		 * 
		 * @return the int
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see java.io.InputStream#read()
		 */
		@Override
		public synchronized int read() throws IOException {

			int b = in.read();
			if (b == str[0] && matchReaminingChars()) {
				b = in.read();
			}

			return b;
		}
	}

	/**
	 * Interface used to piece together specific types of search paths.
	 * Impelementing class defines whatever mechanism, use of properties, file
	 * checks and defualt values that are deemed neccessary to produce an IO
	 * Stream.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public interface SearchPath {
		
		/**
		 * Gets the file.
		 * 
		 * @param name
		 *          the name
		 * @return the file
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 */
		public File getFile(String name) throws IOException;

		/**
		 * Gets the input stream.
		 * 
		 * @param name
		 *          the name
		 * @return the input stream
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 */
		public InputStream getInputStream(String name) throws IOException;

		/**
		 * Gets the uRL.
		 * 
		 * @param name
		 *          the name
		 * @return the uRL
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 */
		public URL getURL(String name) throws IOException;

		/**
		 * Gets the dir.
		 * 
		 * @param name
		 *          the name
		 * @return the dir
		 */
		public File getDir(String name);
	}

	/**
	 * The Class URLSearch.
	 */
	protected static class URLSearch implements SearchPath {

		/** The url. */
		private final ConfigString url;

		/**
		 * Instantiates a new uRL search.
		 * 
		 * @param url
		 *          the url
		 */
		public URLSearch(ConfigString url) {
			this.url = url;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		/**
		 * Gets the file.
		 * 
		 * @param name
		 *          the name
		 * @return the file
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getFile(java.lang.String)
		 */
		public File getFile(String name) throws IOException {
			return null;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.JConfig.SearchPath#get(java.lang.String)
		 */
		/**
		 * Gets the input stream.
		 * 
		 * @param name
		 *          the name
		 * @return the input stream
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getInputStream(java.lang.String)
		 */
		public InputStream getInputStream(String name) throws IOException {
			url.reset();

			if (url.expand(name, globalVariables, topReadOnlyProperties)) {
				final String s = url.toString();

				URL u = null;
				try {
					u = new URL(s);
				} catch (IOException e) {

					/*
					 * For debug purposes, we rebuild from template by explanding just the
					 * variables and leaving the property names unexpanded. The full
					 * template string is hard to understand when the variables aren't
					 * expanded.
					 */
					url.reset().expand(name, globalVariables);
					logger.log(Level.WARNING, "URL: invalid URL format after expansion '"
					    + s + "' property='" + url.toString() + "'");

					return null;
				}

				InputStream in = u.openStream();
				if (in != null) {
					logger.log(Level.FINER, "URL: opened " + s);
					return in;

				} else {
					logger.log(Level.FINEST, "URL: not found " + s);
				}
			} else {
				logger.log(Level.FINEST, "URL: failed to expand " + url.toString());
			}

			return null;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.JConfig.SearchPath#get(java.lang.String)
		 */
		/**
		 * Gets the uRL.
		 * 
		 * @param name
		 *          the name
		 * @return the uRL
		 * @throws IOException
		 *           Signals that an I/O exception has occurred.
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getURL(java.lang.String)
		 */
		public URL getURL(String name) throws IOException {
			url.reset();

			if (url.expand(name, globalVariables, topReadOnlyProperties)) {
				final String s = url.toString();

				URL u = null;
				try {
					u = new URL(s);
				} catch (IOException e) {

					/*
					 * For debug purposes, we rebuild from template by explanding just the
					 * variables and leaving the property names unexpanded. The full
					 * template string is hard to understand when the variables aren't
					 * expanded.
					 */
					url.reset().expand(name, globalVariables);
					logger.log(Level.WARNING, "URL: invalid URL format after expansion '"
					    + s + "' property='" + url.toString() + "'");

					return null;
				}

				InputStream in = u.openStream();
				if (in != null) {
					in.close();
					logger.log(Level.FINER, "URL: opened " + s);
					return u;

				} else {
					logger.log(Level.FINEST, "URL: not found " + s);
				}
			} else {
				logger.log(Level.FINEST, "URL: failed to expand " + url.toString());
			}

			return null;
		}

		/**
		 * To string.
		 * 
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		public String toString() {
			return "URL(" + url.getTemplate() + ")";
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		/**
		 * Gets the dir.
		 * 
		 * @param name
		 *          the name
		 * @return the dir
		 * @see org.jnetpcap.util.config.JConfig.SearchPath#getDir(java.lang.String)
		 */
		public File getDir(String name) {
			return null;
		}

	}

	/** The Constant BOOTSTRAP_SEARCH_PATH. */
	private static final String BOOTSTRAP_SEARCH_PATH =
	    "config.bootstrap.search.path";

	/** The Constant builtinDefaults. */
	private final static Properties builtinDefaults;

	/**
	 * Java property for resolver directory where resolver files are saved.
	 * Property name is {@value #CACHE_DIR_PROPERTY}.
	 */
	public static final String CACHE_DIR_PROPERTY = "jnetpcap.resolver.dir";

	/**
	 * Suffix of a resolver file. Default is {@value #CACHE_FILE_SUFFIX}.
	 */
	public static final String CACHE_FILE_SUFFIX = ".resolver";

	/**
	 * Suffix of a resolver file. Property name is
	 * {@value #CACHE_FILE_SUFFIX_PROPERTY}.
	 */
	public static final String CACHE_FILE_SUFFIX_PROPERTY =
	    "jnetpcap.resolver.suffix";

	/**
	 * If resolver directory is not explicitely defined with a property, this is
	 * the default sub directory name used in user's home directory for all
	 * resolver files. Default is {@value #CACHE_SUB_DIR}.
	 */
	public static final String CACHE_SUB_DIR = ".jnp";

	/**
	 * If resolver directory is not explicitely defined with a.
	 * {@value #CACHE_DIR_PROPERTY}, this is the default sub directory name used
	 * in user's home directory for all resolver files. The property name is
	 * {@value #CACHE_SUB_DIR_PROPERTY}.
	 */
	public static final String CACHE_SUB_DIR_PROPERTY =
	    "jnetpcap.resolver.subdir";

	/** The Constant CONFIG_PROPERTY. */
	private static final String CONFIG_PROPERTY = "config.name";

	/** The global variables. */
	private static Map<String, String> globalVariables =
	    new HashMap<String, String>();

	/** The Constant listeners. */
	private final static PropertyChangeSupport listeners;

	/** The logger. */
	private static Logger logger = JLogger.getLogger(JConfig.class);

	/** The Constant LOGGER_NAME. */
	private static final String LOGGER_NAME = "logger.name";

	/** The Constant LOGGER_SEARCH_PATH. */
	private static final String LOGGER_SEARCH_PATH = "logger.search.path";

	/** The Constant loggingProperties. */
	private final static CompositeProperties loggingProperties;

	/** The Constant RESOURCE_SEARCH_PATH_PROPERTY. */
	public static final String RESOURCE_SEARCH_PATH_PROPERTY = "search.path";

	/** The Constant topReadOnlyProperties. */
	private final static CompositeProperties topReadOnlyProperties;

	/**
	 * System property name used to lookup user's home directory. The property
	 * name is {@value #USER_HOME_PROPERTY}.
	 */
	public static final String USER_HOME_PROPERTY = "user.home";

	/** The Constant userProperties. */
	private final static Properties userProperties;

	/**
	 * We initialize configuration within static initializer because the order of
	 * initialization is really important and thus has to be initialized from
	 * here.
	 */
	static {
		URL url;

		/*
		 * Step #1 - logger comes from 1.5 JRE, shouldn't provide any exceptions.
		 * This is the reason we don't use JLogger in this static initializer
		 */
		logger = JLogger.getLogger(JConfig.class);

		/*
		 * Step #2 - initialize static global variables that are used in
		 * substitutions for search paths
		 */
		globalVariables.put("jnp", "org.jnetpcap");

		/*
		 * Initialization step #2 - initialize configuration properties
		 */

		builtinDefaults = new Properties();

		try {
			url =
			    JConfig.class.getClassLoader().getResource(
			        "resources/builtin-config.properties");
			if (url == null) {
				logger
				    .severe("JConfig.static<>: unable to find builtin-config.properites. "
				        + "Is resources directory in JAR file?");
			} else {
				builtinDefaults.load(new PreprocessStream(url.openStream()));
				logger.fine("loaded " + url.toString());
			}
		} catch (Exception e) {
			logger.log(Level.SEVERE, "builtin config intialization", e);
		}

		/*
		 * Now create properties object we can modify. This is the object that will
		 * be saved and use for user defined config.properties if found. We create
		 * an empty one here so we can build the composite with the right evaluation
		 * order.
		 */
		userProperties = new Properties();

		topReadOnlyProperties =
		    new CompositeProperties(System.getProperties(), userProperties,
		        builtinDefaults);
		topReadOnlyProperties.setSaveProperties(userProperties);

		/*
		 * Export all properties that start with a var.* to global variables
		 */
		exportPropertiesToVariables(topReadOnlyProperties);

		/*
		 * Now search for user defined config properites. Property name looked up is
		 * "config.name". We need name so we can look for this specific resource in
		 * the entire search path.
		 */
		String config = getProperty(CONFIG_PROPERTY);

		try {
			url = getURL(config, BOOTSTRAP_SEARCH_PATH);
			if (url != null) {
				userProperties.load(url.openStream());

				/*
				 * Now export any variables this config file had defined
				 */
				exportPropertiesToVariables(userProperties);

				logger.fine("loaded " + url.toString());
			}
		} catch (IOException e) {
			logger.log(Level.SEVERE, "user config intialization", e);
		}

		loggingProperties = new CompositeProperties();
		Properties builtinLoggerProperties = new Properties();
		try {
			url = getURL("builtin-logger.properties", LOGGER_SEARCH_PATH);

			if (url == null) {
				logger
				    .severe("JConfig.static<>3: unable to find builtin-logger.properties. "
				        + "Is resources directory in JAR file?");

			} else {
				builtinLoggerProperties.load(url.openStream());
				logger.fine("loaded " + url.toString());

				Properties userLoggerProperties = new Properties();
				url = getURL(getProperty(LOGGER_NAME), LOGGER_SEARCH_PATH);
				if (url != null) {
					userLoggerProperties.load(url.openStream());
					loggingProperties.addProperties(userProperties,
					    builtinLoggerProperties);

					Level level = logger.getLevel();
					JLogger.readConfiguration(loggingProperties);
					logger.setLevel(level);
					logger.fine("loaded " + url.toString());
					logger.fine("logger config reinitialized from user settings");
					logger.fine("restoring logging to Level." + level);

				} else {
					/*
					 * No need to reinitialize, JLogger already initialized to builtins.
					 */
					loggingProperties.addProperties(builtinLoggerProperties);
				}
			}

		} catch (Exception e) {
			logger.log(Level.WARNING, "logger config intialization error", e);
		}

		listeners = new PropertyChangeSupport(topReadOnlyProperties);
	}

	/**
	 * Adds listener on any property change event.
	 * 
	 * @param listener
	 *          the listener
	 * @param defaults
	 *          the defaults
	 */
	public static void addListener(
	    PropertyChangeListener listener,
	    String defaults) {

		listeners.addPropertyChangeListener(listener);
	}

	/**
	 * Adds the listener.
	 * 
	 * @param listener
	 *          the listener
	 * @param property
	 *          the property
	 * @param defaults
	 *          the defaults
	 */
	public static void addListener(
	    PropertyChangeListener listener,
	    String property,
	    boolean defaults) {
		addListener(listener, property, Boolean.toString(defaults));
	}

	/**
	 * Adds the listener.
	 * 
	 * @param listener
	 *          the listener
	 * @param property
	 *          the property
	 * @param defaults
	 *          the defaults
	 */
	public static void addListener(
	    PropertyChangeListener listener,
	    String property,
	    int defaults) {
		addListener(listener, property, Integer.toString(defaults));
	}

	/**
	 * Adds the listener.
	 * 
	 * @param listener
	 *          the listener
	 * @param property
	 *          the property
	 * @param defaults
	 *          the defaults
	 */
	public static void addListener(
	    PropertyChangeListener listener,
	    String property,
	    long defaults) {
		addListener(listener, property, Long.toString(defaults));
	}

	/**
	 * Adds the listener.
	 * 
	 * @param listener
	 *          the listener
	 * @param property
	 *          the property
	 * @param defaults
	 *          the defaults
	 */
	public static void addListener(
	    PropertyChangeListener listener,
	    String property,
	    String defaults) {
		listeners.addPropertyChangeListener(property, listener);

		String old = getProperty(property);
		if (old == null) {
			if (defaults != null) {
				setProperty(property, defaults);
			}
		} else {
			listener.propertyChange(new PropertyChangeEvent(topReadOnlyProperties,
			    property, null, old));
		}
	}

	/**
	 * Creates the search path.
	 * 
	 * @param property
	 *          the property
	 * @return the search path[]
	 */
	public static SearchPath[] createSearchPath(String property) {

		String s = topReadOnlyProperties.getProperty(property);
		if (s == null) {
			return null;
		}

		SearchpathString ss =
		    new SearchpathString(s, globalVariables, topReadOnlyProperties);
		SearchPath[] path = ss.toArray();

		return path;
	}

	/**
	 * Export properties to variables.
	 * 
	 * @param properties
	 *          the properties
	 */
	private static void exportPropertiesToVariables(Properties properties) {
		for (Object o : topReadOnlyProperties.keySet()) {
			String key = (String) o;

			if (key.startsWith("var.")) {
				String value = topReadOnlyProperties.getProperty(key);

				globalVariables.put(key.substring(4), value);
			}
		}
	}

	/**
	 * Gets the file.
	 * 
	 * @param name
	 *          the name
	 * @param paths
	 *          the paths
	 * @return the file
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static File getFile(String name, SearchPath[] paths)
	    throws IOException {

		if (paths == null) {
			return null;
		}

		File file = null;

		logger.log(Level.FINEST, "searching file for " + name);

		for (SearchPath path : paths) {
			if ((file = path.getFile(name)) != null) {
				break;
			}
		}

		return file;
	}

	/**
	 * Gets the file.
	 * 
	 * @param name
	 *          the name
	 * @param property
	 *          the property
	 * @return the file
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static File getFile(String name, String property) throws IOException {
		if (topReadOnlyProperties.containsKey(property) == false) {
			return null;
		}
		return getFile(name, createSearchPath(property));
	}

	/**
	 * Gets the input stream.
	 * 
	 * @param name
	 *          the name
	 * @param paths
	 *          the paths
	 * @return the input stream
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static InputStream getInputStream(String name, SearchPath[] paths)
	    throws IOException {

		if (paths == null) {
			return null;
		}

		InputStream in = null;

		logger.log(Level.FINEST, "searching InputStream for " + name);

		for (SearchPath path : paths) {
			if ((in = path.getInputStream(name)) != null) {
				break;
			}
		}

		return in;
	}

	/**
	 * Gets the input stream.
	 * 
	 * @param name
	 *          the name
	 * @param property
	 *          the property
	 * @return the input stream
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static InputStream getInputStream(String name, String property)
	    throws IOException {
		if (topReadOnlyProperties.containsKey(property) == false) {
			return null;
		}

		SearchPath[] path = createSearchPath(property);

		return getInputStream(name, path);
	}

	/**
	 * Gets the property.
	 * 
	 * @param property
	 *          the property
	 * @return the property
	 */
	public static String getProperty(String property) {
		return topReadOnlyProperties.getProperty(property);
	}

	/**
	 * Gets the expanded property.
	 * 
	 * @param property
	 *          the property
	 * @return the expanded property
	 */
	public static String getExpandedProperty(String property) {
		ConfigString s =
		    new ConfigString(getProperty(property), globalVariables,
		        topReadOnlyProperties);
		if (s.expand("")) {
			return s.toString();
		} else {
			return null;
		}
	}

	/**
	 * Gets the expanded property.
	 * 
	 * @param property
	 *          the property
	 * @param defaults
	 *          the defaults
	 * @return the expanded property
	 */
	public static String getExpandedProperty(String property, String defaults) {
		if (topReadOnlyProperties.containsKey(property) == false) {
			return defaults;
		}

		ConfigString s =
		    new ConfigString(getProperty(property), globalVariables,
		        topReadOnlyProperties);
		if (s.expand("")) {
			return s.toString();
		} else {
			return defaults;
		}
	}

	/**
	 * Gets the property.
	 * 
	 * @param property
	 *          the property
	 * @param defaults
	 *          the defaults
	 * @return the property
	 */
	public static String getProperty(String property, final String defaults) {
		return topReadOnlyProperties.getProperty(property, defaults);
	}

	/**
	 * Gets the resource input stream.
	 * 
	 * @param name
	 *          the name
	 * @return the resource input stream
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static InputStream getResourceInputStream(String name)
	    throws IOException {
		return getInputStream(name, RESOURCE_SEARCH_PATH_PROPERTY);
	}

	/**
	 * Gets the resource url.
	 * 
	 * @param name
	 *          the name
	 * @return the resource url
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static URL getResourceURL(String name) throws IOException {
		return getURL(name, RESOURCE_SEARCH_PATH_PROPERTY);
	}

	/**
	 * Gets the uRL.
	 * 
	 * @param name
	 *          the name
	 * @param paths
	 *          the paths
	 * @return the uRL
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	private static URL getURL(String name, SearchPath[] paths) throws IOException {
		URL in = null;

		if (paths == null) {
			return null;
		}

		logger.log(Level.FINEST, "searching URL for " + name);

		for (SearchPath path : paths) {
			if ((in = path.getURL(name)) != null) {
				break;
			}
		}

		return in;
	}

	/**
	 * Gets the uRL.
	 * 
	 * @param name
	 *          the name
	 * @param property
	 *          the property
	 * @return the uRL
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static URL getURL(String name, String property) throws IOException {
		if (topReadOnlyProperties.containsKey(property) == false) {
			return null;
		}

		return getURL(name, createSearchPath(property));
	}

	/**
	 * Inits the.
	 */
	public static void init() {
	}

	/**
	 * Removes the listener.
	 * 
	 * @param listener
	 *          the listener
	 */
	public static void removeListener(PropertyChangeListener listener) {
		listeners.removePropertyChangeListener(listener);
	}

	/**
	 * Removes the listener.
	 * 
	 * @param listener
	 *          the listener
	 * @param property
	 *          the property
	 */
	public static void removeListener(
	    PropertyChangeListener listener,
	    String property) {
		listeners.removePropertyChangeListener(property, listener);
	}

	/**
	 * Sets the property.
	 * 
	 * @param property
	 *          the property
	 * @param value
	 *          the value
	 * @return the string
	 */
	public static String setProperty(String property, String value) {
		String old = (String) userProperties.setProperty(property, value);

		listeners.firePropertyChange(property, old, value);

		return old;
	}

	/**
	 * Gets the dir.
	 * 
	 * @param paths
	 *          the paths
	 * @return the dir
	 */
	public static File getDir(SearchPath[] paths) {
		File file = null;

		if (paths == null) {
			logger.warning("null search path for directory ");
			return null;
		}

		logger.log(Level.FINEST, "searching file for directory");

		for (SearchPath path : paths) {
			if ((file = path.getDir("")) != null) {
				break;
			}
		}

		return file;

	}

	/**
	 * Gets the dir.
	 * 
	 * @param property
	 *          the property
	 * @return the dir
	 */
	public static File getDir(String property) {
		SearchPath[] paths = createSearchPath(property);

		return getDir(paths);
	}

	/**
	 * Creates the dir.
	 * 
	 * @param property
	 *          the property
	 * @param defaults
	 *          the defaults
	 * @return the file
	 */
	public static File createDir(String property, String defaults) {
		String s = topReadOnlyProperties.getProperty(property);
		if (s == null) {
			logger.finer("create directory property not found " + property);
			logger.finer("create directory using defaults " + defaults);
			s = defaults;
		}

		ConfigString home =
		    new ConfigString(s, globalVariables, topReadOnlyProperties);
		if (home.expand("") == false) {
			logger.finer("create directory property expansion failed "
			    + home.toString());

			home.setTemplate(defaults);
			if (home.expand("") == false) {
				logger.finer("create directory defaults expansion failed "
				    + home.toString());
				return null;
			}
		}

		File dir = new File(home.toString());

		if (dir.mkdir() == false) {
			logger.fine("failed to created dir " + dir.toString());
			return null;
		}

		logger.fine("created dir " + dir.toString());

		return dir;
	}

	/**
	 * Creates the config string.
	 * 
	 * @param str
	 *          the str
	 * @return the config string
	 */
	public static ConfigString createConfigString(String str) {
		return new ConfigString(str, globalVariables, topReadOnlyProperties);
	}

	/**
	 * Creates the search string.
	 * 
	 * @param str
	 *          the str
	 * @return the searchpath string
	 */
	public static SearchpathString createSearchString(String str) {
		return new SearchpathString(str, globalVariables, topReadOnlyProperties);
	}

	/**
	 * Gets the top properties.
	 * 
	 * @return the top properties
	 */
	public static Properties getTopProperties() {
		return topReadOnlyProperties;
	}

	/**
	 * Gets the user properties.
	 * 
	 * @return the user properties
	 */
	public static Properties getUserProperties() {
		return userProperties;
	}

	/**
	 * Gets the global variables.
	 * 
	 * @return the global variables
	 */
	public static Map<String, String> getGlobalVariables() {
		return globalVariables;
	}
}
