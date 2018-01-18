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

import java.util.Iterator;

// TODO: Auto-generated Javadoc
/**
 * The Class LinkSequence.
 * 
 * @param <T>
 *          the generic type
 * @author markbe
 */
public class LinkSequence<T> implements Iterable<T> {

	/** The name. */
	private final String name;

	/**
	 * Instantiates a new link sequence.
	 */
	public LinkSequence() {
		this.name = super.toString();
	}

	/**
	 * Instantiates a new link sequence.
	 * 
	 * @param name
	 *          the name
	 */
	public LinkSequence(String name) {
		this.name = name;
	}

	/** The first. */
	private Link<T> first;
	
	/** The last. */
	private Link<T> last;

	/** The size. */
	private int size;

	/**
	 * Adds the.
	 * 
	 * @param l
	 *          the l
	 */
	public synchronized void add(Link<T> l) {
		if (l.linkNext() != null || l.linkPrev() != null) {
			throw new IllegalStateException("link element already part of list");
		}

		if (last == null) {
			first = l;
			last = l;
		} else {
			last.linkNext(l);
			l.linkPrev(last);
			last = l;
		}

		size++;
		l.linkCollection(this);
	}

	/**
	 * Checks if is empty.
	 * 
	 * @return true, if is empty
	 */
	public synchronized boolean isEmpty() {
		return size == 0;
	}

	/**
	 * Removes the.
	 * 
	 * @param l
	 *          the l
	 */
	public synchronized void remove(Link<T> l) {
		final Link<T> p = l.linkPrev();
		final Link<T> n = l.linkNext();

		if (p == null && n == null) { // Only element in the list
			first = null;
			last = null;

		} else if (p == null) { // The first of many elements on the list
			first = n;
			first.linkPrev(null);

		} else if (n == null) { // The last of many elements on the list
			last = p;
			last.linkNext(null);

		} else { // In the middle of many

			p.linkNext(n);
			n.linkPrev(p);
		}

		l.linkNext(null);
		l.linkPrev(null);
		l.linkCollection(null);

		size--;

		if (size < 0) {
			final T e = l.linkElement();
			final String name = (e == null) ? null : e.getClass().getSimpleName();
			String msg =
					String.format("%s:: size < 0 :: culprit=%s[%s]",
							this.name,
							name,
							String.valueOf(e));
			throw new IllegalStateException(msg);
		}
	}

	/**
	 * Size.
	 * 
	 * @return the int
	 */
	public synchronized int size() {
		return size;
	}

	/**
	 * Gets the.
	 * 
	 * @param index
	 *          the index
	 * @return the t
	 */
	public synchronized T get(int index) {
		if (index < 0 || index >= size) {
			throw new IndexOutOfBoundsException(String.format("index=%d, size=%d",
					index,
					size));
		}

		Link<T> l = first;
		int i = 0;
		while (i < index) {
			l = l.linkNext();
			i++;
		}

		return (l == null) ? null : l.linkElement();
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		StringBuilder b = new StringBuilder();

		b.append('[');
		Link<T> node = first;
		while (node != null) {
			if (node != first) {
				b.append(',');
			}

			b.append(node.toString());

			node = node.linkNext();
		}
		b.append(']');

		return b.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Iterable#iterator()
	 */
	/**
	 * Iterator.
	 * 
	 * @return the iterator
	 * @see java.lang.Iterable#iterator()
	 */
	public Iterator<T> iterator() {
		return new Iterator<T>() {

			Link<T> node = first;

			public boolean hasNext() {
				return node != null;
			}

			public T next() {
				Link<T> prev = node;
				node = node.linkNext();
				return prev.linkElement();
			}

			public void remove() {
				throw new UnsupportedOperationException();
			}

		};
	}
}
