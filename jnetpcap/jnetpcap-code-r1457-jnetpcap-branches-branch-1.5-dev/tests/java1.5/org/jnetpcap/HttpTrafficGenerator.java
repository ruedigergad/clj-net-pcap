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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;

// TODO: Auto-generated Javadoc
/**
 * <p>
 * A utility class that is used in conjunction with jUnit test cases that makes
 * a HTTP connection to some website and pulls webpages down. This in tern
 * creates packets for jUnit test cases to catch and perform their tests.
 * Without a forced traffic generator, tests cases have to wait for random
 * packets to arrive.
 * </p>
 * <p>
 * The generator runs in a separate thread and uses a URL object to a website to
 * open a connection in a loop, with lots of delays, to generate a very small
 * amount of traffic for jUnit tests to assert against. The tearDown() method
 * should invoke the HttpTrafficGenerator.stop method, weather the generator was
 * ever started or not. Its always to call stop, even when not running. This is
 * the safest way to guarrantee that we don't end up with some runaway
 * generators. Also as a backup fail mechanism generator only runs for 5 seconds
 * and then stops automatically.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class HttpTrafficGenerator implements Runnable {

	/** The Constant SLEEP. */
	private static final long SLEEP = 100; // 100 millis

	/** The timeout. */
	private long timeout = 5 * 1000; // Timeout in 5 seconds

	/**
	 * Allows multiple threads to access/modify at the same time without synchs.
	 */
	private final AtomicBoolean runflag = new AtomicBoolean(false);

	/** The worker. */
	private final Thread worker;

	/** The website. */
	private URL website;

	/**
	 * Sets the timeout and website to connect to which in tern generates the
	 * traffic.
	 * 
	 * @param timeout
	 *          in millis
	 * @param website
	 *          valid website
	 */
	public HttpTrafficGenerator(long timeout, URL website) {
		this.timeout = timeout;
		this.website = website;

		worker = new Thread(this, "HttpTrafficGenerator");
	}

	/**
	 * Sets the timeout after which the generator stops on its own. A safety
	 * percaution.
	 * 
	 * @param timeout
	 *          the timeout
	 */
	public HttpTrafficGenerator(long timeout) {
		this.timeout = timeout;

		worker = new Thread(this, "HttpTrafficGenerator");
		try {
			website = new URL("http://google.com");
		} catch (MalformedURLException e) {
			throw new IllegalStateException("Internal error", e);
		}
	}

	/**
	 * Use default timeout of 5 seconds, then generator stops on its own. A safety
	 * percaution.
	 */
	public HttpTrafficGenerator() {

		worker = new Thread(this, "HttpTrafficGenerator");
		try {
			website = new URL("http://google.com");
		} catch (MalformedURLException e) {
			throw new IllegalStateException("Internal error", e);
		}
	}

	/**
	 * Starts up the worker thread in the background. Can only be called after
	 * stop. The worker thread can not be running nor can the runflag be set to
	 * true, otherwise exception will be thrown.
	 */
	public void start() {

		if (worker.isAlive()) {
			throw new IllegalStateException(
			    "Worker thread is still alive, unexpected.");
		}

		if (runflag.get()) {
			throw new IllegalStateException(
			    "Runflag is inconsistant with thread, unexpected.");
		}

		runflag.set(true);
		worker.start();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Runnable#run()
	 */
	public void run() {

		long ts = System.currentTimeMillis();

		int count = 0;
		while (runflag.get()) {
			try {
				Object o = website.getContent(); // Get the webpage

				// System.out.printf("Worker working. content=%s\n", o.toString());

				Thread.sleep(SLEEP); // 100 millis

			} catch (Exception e) {
				e.printStackTrace();
				break;
			}

			if (System.currentTimeMillis() - ts > timeout) {
				break; // Break out on our own
			}
			count++;
		}

		/*
		 * Just incase we use break to breakout of the loop, we need to make sure
		 * runflag is consistant with the worker thread state.
		 */
		runflag.set(false);
	}

	/**
	 * Signals the worker thread to end as soon as possible.
	 */
	public void stop() {
		runflag.set(false);

		while (worker.isAlive()) {
			try {
				Thread.sleep(10); // Wait until it stops
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
}
