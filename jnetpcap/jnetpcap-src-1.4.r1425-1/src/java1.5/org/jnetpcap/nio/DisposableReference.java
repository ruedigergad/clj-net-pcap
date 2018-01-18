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

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;

// TODO: Auto-generated Javadoc
/**
 * A reference, who's data can be disposed of using {@link #dispose()} method
 * invokation. The Reference also implements the Link interface which allows the
 * object to be used in a linked-list of DisposableReference objects managed by
 * {@link LinkSequence} stored in global {@link DisposableGC} object.
 * <p>
 * DisposableReference extends WeakReference functionality by allowing
 * DisposableGC to keep a hardreference to the reference (not the referant) to
 * keep it in memory. Through the use of a {@link ReferenceQueue}, DisposableGC
 * is notified when real objects (referants) are garbage collected. This class
 * only keeps a weak reference to referants, but all cleanup information is also
 * stored in subclass of this class. Specifically by calling on subclassed
 * dispose() method, it allows the subclass to perform cleanup after an object,
 * that has already been deleted from memory. For example JMemoryReference
 * class, deallocates native memory, after the JMemory object that was using
 * that native memory is already gone. The JMemoryReference remains as our
 * subclass and has the address of native memory that needs to be reclaimed.
 * </p>
 * 
 * @author markbe
 * 
 */
public abstract class DisposableReference extends PhantomReference<Object>
		implements Disposable, Link<DisposableReference> {

	/*
	 * Since DisposableGC needs to keep a hard reference to us, so that the
	 * DisposableReference part of the Object and Reference combo doesn't get
	 * GCed either, this class implements the Link interface. Its a linked list
	 * of objects that keep references to object before and an object after.
	 * This relationship is maintained by an instance of LinkSequence class in
	 * DisposableGC. This class should not attempt to modify any link fields
	 * directly. All access should be done through a live instance of
	 * LinkSequence class.
	 */
	/** The Constant gc. */
	private final static DisposableGC gc = DisposableGC.getDefault();

	/** The link next. */
	private Link<DisposableReference> linkNext;

	/** The link prev. */
	private Link<DisposableReference> linkPrev;

	/** The ts. */
	private long ts = System.currentTimeMillis();

	/** The link collection. */
	private LinkSequence<DisposableReference> linkCollection;

	/**
	 * Instantiates a new disposable reference.
	 * 
	 * @param referant
	 *            the referant
	 */
	public DisposableReference(Object referant) {
		super(referant, gc.refQueue);

		gc.addReference(this);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.mem.Disposable#dispose()
	 */
	/**
	 * Dispose.
	 * 
	 * @see org.jnetpcap.nio.Disposable#dispose()
	 */
	public void dispose() {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkElement()
	 */
	/**
	 * Link element.
	 * 
	 * @return the disposable reference
	 * @see org.jnetpcap.nio.Link#linkElement()
	 */
	public DisposableReference linkElement() {
		return this;
	}

	/**
	 * Link collection.
	 * 
	 * @return the link sequence
	 * @see org.jnetpcap.nio.Link#linkCollection()
	 */
	public LinkSequence<DisposableReference> linkCollection() {
		return linkCollection;
	}

	/**
	 * Link collection.
	 * 
	 * @param collection
	 *            the collection
	 * @see org.jnetpcap.nio.Link#linkCollection(org.jnetpcap.nio.LinkSequence)
	 */
	public void linkCollection(LinkSequence<DisposableReference> collection) {
		this.linkCollection = collection;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkNext()
	 */
	/**
	 * Link next.
	 * 
	 * @return the link
	 * @see org.jnetpcap.nio.Link#linkNext()
	 */
	public Link<DisposableReference> linkNext() {
		return linkNext;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkNext(org.jnetlib.util.Link)
	 */
	/**
	 * Link next.
	 * 
	 * @param l
	 *            the l
	 * @see org.jnetpcap.nio.Link#linkNext(org.jnetpcap.nio.Link)
	 */
	public void linkNext(Link<DisposableReference> l) {
		linkNext = l;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkPrev()
	 */
	/**
	 * Link prev.
	 * 
	 * @return the link
	 * @see org.jnetpcap.nio.Link#linkPrev()
	 */
	public Link<DisposableReference> linkPrev() {
		return linkPrev;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkPrev(org.jnetlib.util.Link)
	 */
	/**
	 * Link prev.
	 * 
	 * @param l
	 *            the l
	 * @see org.jnetpcap.nio.Link#linkPrev(org.jnetpcap.nio.Link)
	 */
	public void linkPrev(Link<DisposableReference> l) {
		linkPrev = l;
	}

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return String.format("prev=%s, next=%s", linkPrev, linkNext);
	}

	/**
	 * Removes the.
	 */
	public void remove() {
		linkCollection().remove(this);
		super.clear();
	}

	/**
	 * Size.
	 * 
	 * @return the int
	 */
	public int size() {
		return 0;
	}

	/**
	 * Gets the ts.
	 * 
	 * @return the ts
	 */
	public long getTs() {
		return ts;
	}

	/**
	 * Sets the ts.
	 * 
	 * @param ts
	 *            the ts to set
	 */
	public void setTs(long ts) {
		this.ts = ts;
	}
}
