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

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.jnetpcap.util.JLogger;

// TODO: Auto-generated Javadoc
/**
 * A resolver object that knows how to convert IP addresses into hostnames.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class IpResolver
    extends AbstractResolver {

	/**
	 * Instantiates a new ip resolver.
	 * 
	 */
	public IpResolver() {
		super(JLogger.getLogger(IpResolver.class), "IP");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter.AbstractResolver#resolveToName(byte[],
	 *      int)
	 */
	/**
	 * Resolve to name.
	 * 
	 * @param address
	 *          the address
	 * @param hash
	 *          the hash
	 * @return the string
	 * @see org.jnetpcap.util.resolver.AbstractResolver#resolveToName(byte[],
	 *      long)
	 */
	@Override
	public String resolveToName(byte[] address, long hash) {
		try {
			InetAddress i = InetAddress.getByAddress(address);
			String host = i.getHostName();
			if (Character.isDigit(host.charAt(0)) == false) {
				return host;
			}

		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return null;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter.AbstractResolver#toHashCode(byte[])
	 */
	/**
	 * To hash code.
	 * 
	 * @param address
	 *          the address
	 * @return the long
	 * @see org.jnetpcap.util.resolver.AbstractResolver#toHashCode(byte[])
	 */
	@Override
	public long toHashCode(byte[] address) {
		long hash =
		    ((address[3] < 0) ? address[3] + 256 : address[3])
		        | ((address[2] < 0) ? address[2] + 256 : address[2]) << 8
		        | ((address[1] < 0) ? address[1] + 256 : address[1]) << 16
		        | ((address[0] < 0) ? address[0] + 256 : address[0]) << 24;

		return hash;
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