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

// TODO: Auto-generated Javadoc
/**
 * A bindinding between two protocol headers.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JBinding extends JDependency {

	/**
	 * An abstract adaptor that provides a default implementation for a binding.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class DefaultJBinding implements JBinding {

		/** The dependency ids. */
		private final int[] dependencyIds;

		/** The my id. */
		private final int myId;

		/** The target id. */
		private final int targetId;

		/**
		 * Initializes a binding with source ID, target ID and any additional
		 * dendency IDs that need to be specified.
		 * 
		 * @param myId
		 *          ID of the header that owns this binding
		 * @param targetId
		 *          ID of the header to which this binding needs to be applied to.
		 *          The target ID also becomes an automatic dependency since that is
		 *          always the case.
		 * @param dependencyIds
		 *          additional IDs of headers that are referenced in the binding
		 *          expression
		 */
		public DefaultJBinding(int myId, int targetId, int... dependencyIds) {
			this.myId = myId;
			this.targetId = targetId;
			this.dependencyIds = new int[dependencyIds.length + 1];

			System.arraycopy(dependencyIds, 0, this.dependencyIds, 1,
			    dependencyIds.length);

			this.dependencyIds[0] = targetId; // Always the case
		}

		/**
		 * Protocol header ID for this binding.
		 * 
		 * @return numerical ID of the header as assigned by JRegistry
		 */
		public int getId() {
			return myId;
		}

		/**
		 * Protocol header ID to which this binding is bound to.
		 * 
		 * @return numerical protocol ID as assigned by JRegistry
		 */
		public int getTargetId() {
			return targetId;
		}

		/**
		 * A list of dependencies that a binding has.
		 * 
		 * @return list of depdencies
		 */
		public int[] listDependencies() {
			return this.dependencyIds;
		}

	}

	/** A status code that indicates that no protocol was matched. */
	public static final int NULL_ID = -2;

	/**
	 * Protocol header ID to which this binding is bound to.
	 * 
	 * @return numerical protocol ID as assigned by JRegistry
	 */
	public abstract int getTargetId();

	/**
	 * Checks the length of the header that has not been bound yet. The returned
	 * length value provides 2 pieces of information. 1st, length of 0 indicates
	 * that the header is not bound. 2nd, length of non zero indicates that the
	 * header is bound and either the entire or trucated length of the header.
	 * 
	 * @param packet
	 *          packet and its data buffer
	 * @param offset
	 *          offset into the packet data buffer where the end of the previous
	 *          header is
	 * @return either full or truncated length of the header or 0 if header is not
	 *         bound at all
	 */
	public abstract boolean isBound(JPacket packet, int offset);
	

	/**
	 * A list of dependencies that a binding has.
	 * 
	 * @return list of depdencies
	 */
	public int[] listDependencies();

	/**
	 * Protocol header ID for this binding.
	 * 
	 * @return numerical ID of the header as assigned by JRegistry
	 */
	public int getSourceId();
}