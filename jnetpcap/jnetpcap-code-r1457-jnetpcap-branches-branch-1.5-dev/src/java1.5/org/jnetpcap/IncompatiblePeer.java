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
package org.jnetpcap;

// TODO: Auto-generated Javadoc
/**
 * The Class IncompatiblePeer.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class IncompatiblePeer
    extends Exception {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 9081938128324891646L;

	/**
	 * Instantiates a new incompatible peer.
	 * 
	 * @param msg
	 *          the msg
	 */
	public IncompatiblePeer(String msg) {
		super(msg);
	}

}
