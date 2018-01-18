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
package org.jnetpcap.nio;

// TODO: Auto-generated Javadoc
/**
 * The Interface Link.
 * 
 * @param <T>
 *          the generic type
 * @author markbe
 */
public interface Link<T> {
	
	/**
	 * Link next.
	 * 
	 * @return the link
	 */
	public Link<T> linkNext();

	/**
	 * Link next.
	 * 
	 * @param l
	 *          the l
	 */
	public void linkNext(Link<T> l);

	/**
	 * Link prev.
	 * 
	 * @return the link
	 */
	public Link<T> linkPrev();

	/**
	 * Link prev.
	 * 
	 * @param l
	 *          the l
	 */
	public void linkPrev(Link<T> l);

	/**
	 * Link element.
	 * 
	 * @return the t
	 */
	public T linkElement();
	
	/**
	 * Link collection.
	 * 
	 * @return the link sequence
	 */
	public LinkSequence<T> linkCollection();
	
	/**
	 * Link collection.
	 * 
	 * @param c
	 *          the c
	 */
	public void linkCollection(LinkSequence<T> c);
}
