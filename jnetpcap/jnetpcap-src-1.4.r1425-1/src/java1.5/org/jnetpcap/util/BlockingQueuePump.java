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
package org.jnetpcap.util;

import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

// TODO: Auto-generated Javadoc
/**
 * The Class BlockingQueuePump.
 * 
 * @param <T>
 *          the generic type
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class BlockingQueuePump<T> implements BlockingQueue<T> {

	/** The name. */
	private final String name;

	/** The queue. */
	private final BlockingQueue<T> queue;

	/** The thread. */
	private final AtomicReference<Thread> thread = new AtomicReference<Thread>();

	/**
	 * Unlimited capacity queue.
	 * 
	 * @param name
	 *          name to use for the worker thread
	 */
	public BlockingQueuePump(String name) {
		this.queue = new LinkedBlockingQueue<T>();
		this.name = name;

		start();
	}

	/**
	 * A limited in capacity queue.
	 * 
	 * @param name
	 *          name to use for the workder thread
	 * @param capacity
	 *          maximum capacity of the queue
	 */
	public BlockingQueuePump(String name, int capacity) {
		this.queue = new ArrayBlockingQueue<T>(capacity);
		this.name = name;

		start();
	}

	/**
	 * Adds the.
	 * 
	 * @param o
	 *          the o
	 * @return true, if successful
	 * @see java.util.concurrent.BlockingQueue#add(java.lang.Object)
	 */
	public boolean add(T o) {
		return this.queue.add(o);
	}

	/**
	 * Adds the all.
	 * 
	 * @param c
	 *          the c
	 * @return true, if successful
	 * @see java.util.Collection#addAll(java.util.Collection)
	 */
	public boolean addAll(Collection<? extends T> c) {
		return this.queue.addAll(c);
	}

	/**
	 * Clear.
	 * 
	 * @see java.util.Collection#clear()
	 */
	public void clear() {
		this.queue.clear();
	}

	/**
	 * Contains.
	 * 
	 * @param o
	 *          the o
	 * @return true, if successful
	 * @see java.util.Collection#contains(java.lang.Object)
	 */
	public boolean contains(Object o) {
		return this.queue.contains(o);
	}

	/**
	 * Contains all.
	 * 
	 * @param c
	 *          the c
	 * @return true, if successful
	 * @see java.util.Collection#containsAll(java.util.Collection)
	 */
	public boolean containsAll(Collection<?> c) {
		return this.queue.containsAll(c);
	}

	/**
	 * Dispatch.
	 * 
	 * @param data
	 *          the data
	 */
	protected abstract void dispatch(T data);

	/**
	 * Drain to.
	 * 
	 * @param c
	 *          the c
	 * @return the int
	 * @see java.util.concurrent.BlockingQueue#drainTo(java.util.Collection)
	 */
	public int drainTo(Collection<? super T> c) {
		return this.queue.drainTo(c);
	}

	/**
	 * Drain to.
	 * 
	 * @param c
	 *          the c
	 * @param maxElements
	 *          the max elements
	 * @return the int
	 * @see java.util.concurrent.BlockingQueue#drainTo(java.util.Collection, int)
	 */
	public int drainTo(Collection<? super T> c, int maxElements) {
		return this.queue.drainTo(c, maxElements);
	}

	/**
	 * Element.
	 * 
	 * @return the t
	 * @see java.util.Queue#element()
	 */
	public T element() {
		return this.queue.element();
	}

	/**
	 * Equals.
	 * 
	 * @param o
	 *          the o
	 * @return true, if successful
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object o) {
		return this.queue.equals(o);
	}

	/**
	 * Hash code.
	 * 
	 * @return the int
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return this.queue.hashCode();
	}

	/**
	 * Checks if is alive.
	 * 
	 * @return true, if is alive
	 */
	public boolean isAlive() {
		return thread.get() != null && thread.get().isAlive();
	}

	/**
	 * Checks if is empty.
	 * 
	 * @return true, if is empty
	 * @see java.util.Collection#isEmpty()
	 */
	public boolean isEmpty() {
		return this.queue.isEmpty();
	}

	/**
	 * Iterator.
	 * 
	 * @return the iterator
	 * @see java.util.Collection#iterator()
	 */
	public Iterator<T> iterator() {
		return this.queue.iterator();
	}

	/**
	 * Offer.
	 * 
	 * @param o
	 *          the o
	 * @return true, if successful
	 * @see java.util.concurrent.BlockingQueue#offer(java.lang.Object)
	 */
	public boolean offer(T o) {
		return this.queue.offer(o);
	}

	/**
	 * Offer.
	 * 
	 * @param o
	 *          the o
	 * @param timeout
	 *          the timeout
	 * @param unit
	 *          the unit
	 * @return true, if successful
	 * @throws InterruptedException
	 *           the interrupted exception
	 * @see java.util.concurrent.BlockingQueue#offer(java.lang.Object, long,
	 *      java.util.concurrent.TimeUnit)
	 */
	public boolean offer(T o, long timeout, TimeUnit unit)
			throws InterruptedException {
		return this.queue.offer(o, timeout, unit);
	}

	/**
	 * Peek.
	 * 
	 * @return the t
	 * @see java.util.Queue#peek()
	 */
	public T peek() {
		return this.queue.peek();
	}

	/**
	 * Poll.
	 * 
	 * @return the t
	 * @see java.util.Queue#poll()
	 */
	public T poll() {
		return this.queue.poll();
	}

	/**
	 * Poll.
	 * 
	 * @param timeout
	 *          the timeout
	 * @param unit
	 *          the unit
	 * @return the t
	 * @throws InterruptedException
	 *           the interrupted exception
	 * @see java.util.concurrent.BlockingQueue#poll(long,
	 *      java.util.concurrent.TimeUnit)
	 */
	public T poll(long timeout, TimeUnit unit) throws InterruptedException {
		return this.queue.poll(timeout, unit);
	}

	/**
	 * Put.
	 * 
	 * @param o
	 *          the o
	 * @throws InterruptedException
	 *           the interrupted exception
	 * @see java.util.concurrent.BlockingQueue#put(java.lang.Object)
	 */
	public void put(T o) throws InterruptedException {
		this.queue.put(o);
	}

	/**
	 * Remaining capacity.
	 * 
	 * @return the int
	 * @see java.util.concurrent.BlockingQueue#remainingCapacity()
	 */
	public int remainingCapacity() {
		return this.queue.remainingCapacity();
	}

	/**
	 * Removes the.
	 * 
	 * @return the t
	 * @see java.util.Queue#remove()
	 */
	public T remove() {
		return this.queue.remove();
	}

	/**
	 * Removes the.
	 * 
	 * @param o
	 *          the o
	 * @return true, if successful
	 * @see java.util.Collection#remove(java.lang.Object)
	 */
	public boolean remove(Object o) {
		return this.queue.remove(o);
	}

	/**
	 * Removes the all.
	 * 
	 * @param c
	 *          the c
	 * @return true, if successful
	 * @see java.util.Collection#removeAll(java.util.Collection)
	 */
	public boolean removeAll(Collection<?> c) {
		return this.queue.removeAll(c);
	}

	/**
	 * Retain all.
	 * 
	 * @param c
	 *          the c
	 * @return true, if successful
	 * @see java.util.Collection#retainAll(java.util.Collection)
	 */
	public boolean retainAll(Collection<?> c) {
		return this.queue.retainAll(c);
	}

	/**
	 * Size.
	 * 
	 * @return the int
	 * @see java.util.Collection#size()
	 */
	public int size() {
		return this.queue.size();
	}

	/** The dispatch queue. */
	public Runnable dispatchQueue = new Runnable() {

		public void run() {
			try {
				while (thread.get() != null) {
					dispatch(take());
				}

				if (thread.get() != null) {
					throw new IllegalStateException(name
							+ " thread unexpected termination");
				}

			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} finally {
				thread.set(null);
			}
		}

	};

	/**
	 * Start.
	 */
	public void start() {

		if (thread.get() != null) {
			throw new IllegalStateException(name + " thread unexpected termination");
		}

		thread.set(new Thread(dispatchQueue, name));
		thread.get().setDaemon(true);
		thread.get().start();
	}

	/**
	 * Stop.
	 */
	public void stop() {
		if (thread.get() == null || thread.get().isAlive() == false) {
			thread.set(null);
			return;
		}

		synchronized (thread.get()) {
			try {
				thread.wait();
			} catch (InterruptedException e) {
			} finally {
				this.thread.set(null);
			}
		}
	}

	/**
	 * Take.
	 * 
	 * @return the t
	 * @throws InterruptedException
	 *           the interrupted exception
	 * @see java.util.concurrent.BlockingQueue#take()
	 */
	public T take() throws InterruptedException {
		return this.queue.take();
	}

	/**
	 * To array.
	 * 
	 * @return the object[]
	 * @see java.util.Collection#toArray()
	 */
	public Object[] toArray() {
		return this.queue.toArray();
	}

	/**
	 * To array.
	 * 
	 * @param <Q>
	 *          the generic type
	 * @param a
	 *          the a
	 * @return the q[]
	 * @see java.util.Collection#toArray(Object[])
	 */
	public <Q> Q[] toArray(Q[] a) {
		return this.queue.toArray(a);
	}
}
