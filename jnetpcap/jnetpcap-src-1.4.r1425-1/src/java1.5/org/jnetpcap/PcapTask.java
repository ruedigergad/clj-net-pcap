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
 * A pcap background task handle. This provides status and control over the
 * background loop. The task provides 2 methods for controlling the thread.
 * 
 * @param <T>
 *          user supplied type {@link #start()} and {@link #stop()}. These 2
 *          methods perform various synchronization functions between the worker
 *          and the parent threads.
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @since 1.2
 */
public abstract class PcapTask<T> implements Runnable {

	/** Libpcap result code. */
	protected int result = Pcap.OK;

	/** Controlling thread. */
	protected Thread thread;

	/** Pcap handle. */
	protected final Pcap pcap;

	/** Number of packets to capture or 0 for infinate. */
	protected final int count;

	/** User data. */
	protected final T user;

	/**
	 * Creates a new task handle for controlling background thread.
	 * 
	 * @param pcap
	 *          pcap handle
	 * @param count
	 *          number of packets to capture or 0 for infinite
	 * @param user
	 *          user supplied object
	 */
	public PcapTask(Pcap pcap, int count, T user) {
		this.pcap = pcap;
		this.count = count;
		this.user = user;
	}

	/**
	 * Returns the result code that was returned from the user supplied pcap
	 * function.
	 * 
	 * @return libpcap result code
	 */
	public final int getResult() {
		return this.result;
	}

	/**
	 * Gets the background thread this task is using. It is highly recommended
	 * though that the user interact with the thread using {@link #start()} and
	 * 
	 * @return background thread {@link #stop()} methods.
	 */
	public final Thread getThread() {
		return this.thread;
	}

	/**
	 * Creates and starts up the background thread while synchronizing with the
	 * background thread. The user can be assured that when this method returns,
	 * the background thread has been started and has entered its Runnable.run
	 * method.
	 * 
	 * @throws InterruptedException
	 *           if the synchronization between threads was interrupted
	 */
	public void start() throws InterruptedException {
		if (thread != null) {
			stop();
		}

		/*
		 * Use our own Runnable in order to synchronize the start of the thread. We
		 * delegate to the user overriden run() method after the setup synching is
		 * done.
		 */
		thread =
	    new Thread(new Runnable() {

				public void run() {
					PcapTask.this.run();
					thread = null; // Cleanup
        }
	    	
	    }, (user != null) ? user.toString() : pcap.toString());

		thread.setDaemon(true);
		thread.start();
	}

	/**
	 * <p>
	 * Terminates the task after making sure that the pcap session and thread are
	 * active.
	 * </p>
	 * 
	 * @throws InterruptedException
	 *           since this method waits for the background thread to terminate,
	 *           it can be interrupted
	 */
	public void stop() throws InterruptedException {
		if (thread == null || thread.isAlive() == false) {
			/*
			 * Nothing to do
			 */
			return;
		}

		/*
		 * Tell pcap we want to break out of the loop
		 */
		breakLoop();
		thread.join(); // Wait for thread to finish and exit
	}
	
	/**
	 * Algorithm for breaking the loop, whatever it is. It can be overriden and a
	 * different algorithm supplied.
	 */
	protected void breakLoop() {
		pcap.breakloop();
	}

	/**
	 * Checks if the background thread is running and is alive.
	 * 
	 * @return true means thread is alive
	 */
	public boolean isAlive() {
		return thread != null && thread.isAlive();
	}

	/**
	 * Returns the underlying Pcap object being used by this task
	 * 
	 * @return pcap capture session object
	 */
	public final Pcap getPcap() {
		return this.pcap;
	}

	/**
	 * The packet count that was supplied by the user. This is the number of
	 * packets requested by the user. 0 indicates capture forever until
	 * 
	 * @return number of packets to capture or 0 for infinite {@link #stop()} is
	 *         called or an error occures.
	 */
	public final int getCount() {
		return this.count;
	}

	/**
	 * User supplied data object. This is an arbitrary user object.
	 * 
	 * @return user object
	 */
	public final T getUser() {
		return this.user;
	}

}