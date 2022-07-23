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
package org.jnetpcap.winpcap;

import org.jnetpcap.Pcap;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>pcap_rmtauth</code> structure. Provides
 * authentication data for establishing remote capture and lookup operations
 * using WinPcap extensions.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Library(jni = Pcap.LIBRARY)
public final class WinPcapRmtAuth {

	/**
	 * It defines the NULL authentication. This value has to be used within the
	 * 'type' member of the pcap_rmtauth structure. The 'NULL' authentication has
	 * to be equal to 'zero', so that old applications can just put every field of
	 * struct pcap_rmtauth to zero, and it does work.
	 */
	public final static int RMT_AUTH_NULL = 0;

	/**
	 * It defines the username/password authentication. With this type of
	 * authentication, the RPCAP protocol will use the username/ password provided
	 * to authenticate the user on the remote machine. If the authentication is
	 * successful (and the user has the right to open network devices) the RPCAP
	 * connection will continue; otherwise it will be dropped. This value has to
	 * be used within the 'type' member of the pcap_rmtauth structure.
	 */
	public final static int RMT_AUTH_PWD = 1;

	/**
	 * Inits the i ds.
	 */
	@LibraryInitializer
	private native static void initIDs();

	static {
		JNILibrary.register(WinPcapSamp.class);
	}

	/** The type. */
	private int type;

	/** The username. */
	private String username;

	/** The password. */
	private String password;

	/**
	 * Allocates an empty authentication object so that it may be setup.
	 */
	public WinPcapRmtAuth() {

	}

	/**
	 * Allocates and configures authentication object.
	 * 
	 * @param type
	 *          authentication type; values of 0 or 1 permitted
	 * @param username
	 *          string containing the username that has to be used on the remote
	 *          machine for authentication
	 * @param password
	 *          string containing the password that has to be used on the remote
	 *          machine for authentication
	 */
	public WinPcapRmtAuth(int type, String username, String password) {
		this.type = type;
		this.username = username;
		this.password = password;
	}

	/**
	 * Gets the type of the authentication required.
	 * 
	 * @return Type of the authentication required.
	 */
	public final int getType() {
		return this.type;
	}

	/**
	 * Type of the authentication required.
	 * 
	 * @param type
	 *          the type to set
	 */
	public final void setType(int type) {
		this.type = type;
	}

	/**
	 * String containing the username that has to be used on the remote machine
	 * for authentication.
	 * 
	 * @return the username
	 */
	public final String getUsername() {
		return this.username;
	}

	/**
	 * Sets the string containing the username that has to be used on the remote
	 * machine for authentication.
	 * 
	 * @param username
	 *          the username to set
	 */
	public final void setUsername(String username) {
		this.username = username;
	}

	/**
	 * Gets the string containing the password that has to be used on the remote
	 * machine for authentication.
	 * 
	 * @return the password
	 */
	public final String getPassword() {
		return this.password;
	}

	/**
	 * Sets the string containing the password that has to be used on the remote
	 * machine for authentication.
	 * 
	 * @param password
	 *          the password to set
	 */
	public final void setPassword(String password) {
		this.password = password;
	}

}
