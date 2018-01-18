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

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.sql.Time;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.jnetpcap.util.Units;

// TODO: Auto-generated Javadoc
/**
 * Specialized garbage-collector that invokes the.
 * 
 * {@link DisposableReference#dispose} method immediately as soon as a
 * DisposableReference becomes unreferancable and put on the main garbage
 * collector's list.
 * 
 * @author markbe
 */
public final class DisposableGC {

	/** The Constant DEFAULT_CLEANUP_THREAD_TIMEOUT. */
	private static final long DEFAULT_CLEANUP_THREAD_TIMEOUT = 20;

	/** The default gc. */
	private static DisposableGC defaultGC = new DisposableGC();

	/** The Constant G10. */
	private static final long G10 = 10 * 1000;

	/** The Constant G60. */
	private static final long G60 = 60 * 1000;

	/** The Constant MANUAL_DRAING_MAX. */
	static final private int MANUAL_DRAING_MAX = 2;

	/**
	 * When maxDirectMemorySize is breached, this is the minimum amount of
	 * memory to release, triggering a System.gc() if necessary.
	 */
	static final int MIN_MEMORY_RELEASE = 2 * Units.MEBIBYTE;

	/**
	 * Minimum delay before 2 consecutive System.gc calls can be made
	 */
	static final long MIN_SYSTEM_GC_INVOKE_TIMEOUT = 200;

	/** The Constant OUT_OF_MEMORY_TIMEOUT. */
	static final long OUT_OF_MEMORY_TIMEOUT = 15 * 1000;

	/**
	 * Gets the default.
	 * 
	 * @return the default
	 */
	public static DisposableGC getDefault() {
		return defaultGC;
	}

	/**
	 * Mem.
	 * 
	 * @param c
	 *            the c
	 * @return the long
	 */
	private static long mem(LinkSequence<DisposableReference> c) {
		long size = 0;
		for (DisposableReference ref : c) {
			size += ref.size();
		}

		return size;
	}

	/** The cleanup thread. */
	private Thread cleanupThread;

	/** The cleanup thread active. */
	private final AtomicBoolean cleanupThreadActive = new AtomicBoolean(false);

	/** The cleanup thread processing. */
	private final AtomicBoolean cleanupThreadProcessing = new AtomicBoolean(
			false);

	/** The cleanup timeout. */
	private final AtomicLong cleanupTimeout = new AtomicLong(
			DisposableGC.DEFAULT_CLEANUP_THREAD_TIMEOUT);

	/** The delta count. */
	private long deltaCount;

	/** The delta size. */
	private long deltaSize;
	/**
	 * Performance in 1000s of pps using various collection types:
	 * 
	 * <pre>
	 * Type           Threaded   Non-Threaded
	 *                 min-max     min-max
	 * ------------------------------------------------    
	 * ArrayDeque:    43.3-44.8   42.5-44.7
	 * ArrayList:     43.2-44.7   42.9-45.0
	 * LinkedList:    43.7-44.8   42.6-44.5
	 * HashSet:       43.3-44.4   41.2-43.5
	 * LinkedHashSet: 42.4-43.5   43.2-44.3
	 * </pre>
	 */
	// final Collection<DisposableReference> refCollection3 =
	// new ArrayDeque<DisposableReference>(20000);
	// new ArrayList<DisposableReference>(20000);
	// new LinkedList<DisposableReference>();
	// new HashSet<DisposableReference>(20000);
	// new LinkedHashSet<DisposableReference>(20000);

	final LinkSequence<DisposableReference> g0 =
			new LinkSequence<DisposableReference>("g0");

	/** The g10. */
	final LinkSequence<DisposableReference> g10 =
			new LinkSequence<DisposableReference>("g10");

	/** The g60. */
	final LinkSequence<DisposableReference> g60 =
			new LinkSequence<DisposableReference>("g60");

	/** The last system gc invoke. */
	private long lastSystemGCInvoke = 0;

	/** The first system gc needed. */
	private long firstSystemGCNeeded = 0;

	/*
	 * private static class Marker extends PhantomReference<Object> {
	 * 
	 * @SuppressWarnings("unused") public final long id;
	 *//** The marker queue. */
	/*
	 * public Marker(long id) { super(new Object() { },
	 * DisposableGC.getDeault().markerQueue);
	 * 
	 * this.id = id; }
	 * 
	 * }
	 */
	final ReferenceQueue<Object> markerQueue = new ReferenceQueue<Object>();

	/** The marker reference. */
	private Reference<Object> markerReference;

	/** The memory semaphore. */
	private final Semaphore memorySemaphore = new Semaphore(
			DisposableGC.MIN_MEMORY_RELEASE);

	/** The ref queue. */
	final ReferenceQueue<Object> refQueue = new ReferenceQueue<Object>();

	/** The total disposed. */
	private long totalDisposed = 1;

	/** The total size. */
	private long totalSize;

	/** The verbose. */
	private boolean verbose = false;

	/** A bit more verbose. */
	private boolean vverbose = false;

	/** The vvverbose. */
	private boolean vvverbose = false;

	/**
	 * Instantiates a new disposable gc.
	 */
	private DisposableGC() {
		startCleanupThread();

		try {
			setVerbose(Boolean.parseBoolean(System.getProperty("nio.verbose",
					"false")));
			setVVerbose(Boolean.parseBoolean(System.getProperty("nio.vverbose",
					"false")));
			setVVVerbose(Boolean.parseBoolean(System
					.getProperty("nio.vvverbose", "false")));
		} catch (Exception e) {
			// Ignore any formatting exceptions from the command line
		}
	}

	public void addReference(DisposableReference ref) {

		synchronized (g0) {
			g0.add(ref);
			// memorySemaphore.acquire(ref.size());
		}

		if (!isCleanupThreadActive()) {
			drainRefQueueBounded();
		}
	}

	/**
	 * Dispose.
	 * 
	 * @param ref
	 *            the ref
	 */
	private void dispose(DisposableReference ref) {

		try {
			synchronized (g0) {
				memorySemaphore.release(ref.size());

				totalDisposed++;
				totalSize += ref.size();
				ref.dispose();
				ref.remove();

				if (g0.isEmpty() && g10.isEmpty() && g60.isEmpty()) {
					g0.notifyAll();
				}
			}
		} catch (RuntimeException e) {
			logUsage();
			throw e;
		}

	}

	/**
	 * Drain ref queue.
	 */
	public void drainRefQueue() {
		while (true) {
			DisposableReference ref = (DisposableReference) refQueue.poll();
			if (ref == null) {
				break;
			}

			dispose(ref);
		}
	}

	/**
	 * Drain ref queue.
	 * 
	 * @param timeout
	 *            the timeout
	 * @throws IllegalArgumentException
	 *             the illegal argument exception
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	public void drainRefQueue(long timeout) throws IllegalArgumentException,
			InterruptedException {

		memorySemaphore.acquire(memorySemaphore.availablePermits()); // Grab all
		// of
		// them

		/*
		 * Breakup the timeout into 100 partitions so that we can check the
		 * permits more often then just a single monolithic times.
		 */
		long partition = timeout / 100;
		while (memorySemaphore.availablePermits() < MIN_MEMORY_RELEASE) {
			DisposableReference ref =
					(DisposableReference) refQueue.remove(timeout);

			if (ref == null && partition++ < 100) {
				continue;
			}

			if (ref == null) {
				break;
			}

			dispose(ref);
		}
	}

	/**
	 * Drain ref queue bounded.
	 */
	void drainRefQueueBounded() {
		int iterations = 0;
		while (iterations < MANUAL_DRAING_MAX) {
			DisposableReference ref = (DisposableReference) refQueue.poll();
			if (ref == null) {
				break;
			}

			dispose(ref);
			++iterations;
		}
	}

	/**
	 * Drain ref queue loop.
	 * 
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	void drainRefQueueLoop() throws InterruptedException {

		deltaCount = 0;
		deltaSize = 0;
		final long timeout = cleanupTimeout.get();
		long ts = System.currentTimeMillis();
		while (true) {

			final DisposableReference ref =
					(DisposableReference) refQueue.remove(timeout);

			if (ref != null) { // We have a reference to dispose of
				if (deltaCount == 0) { // First one
					if (vvverbose && cleanupThreadProcessing.get() == false) {
						logBusy();
					}
					cleanupThreadProcessing.set(true);
					synchronized (cleanupThreadProcessing) {
						cleanupThreadProcessing.notifyAll(); // Signal start
					}
				}
				deltaCount++;
				deltaSize += ref.size();

				/**
				 * Keep message coming even if we are continuously processing.
				 */
				if (vverbose && (deltaCount % 10000) == 0) {
					sortGenerations();
					logUsage();
				}

				/*
				 * Means, we just finished processing
				 */
			} else if (deltaCount != 0
					&& (System.currentTimeMillis() - ts) >= 1000) {
				ts = System.currentTimeMillis();
				sortGenerations();
				if (verbose && deltaCount > 00) {
					logUsage();
				}

				deltaCount = 0;
				deltaSize = 0;
				cleanupThreadProcessing.set(false);

				synchronized (cleanupThreadProcessing) { // Signal finish
					cleanupThreadProcessing.notifyAll();
				}
				if (vvverbose) {
					logIdle();
				}
			}

			if (ref == null) {
				if (cleanupThreadActive.get()) {
					if (memorySemaphore.hasQueuedThreads()) {
						invokeSystemGC();
					}

					continue; // Null due to timeout
				} else {
					if (verbose) {
						logFinished();
					}
					break;
				}
			}

			if (memorySemaphore.availablePermits() > MIN_MEMORY_RELEASE) {
				memorySemaphore.drainPermits();
			}

			dispose(ref);
		}

		if (verbose && deltaCount != 0) {
			System.out
					.printf("DisposableGC: disposed of %d entries [total=%dM]%n",
							deltaCount,
							totalDisposed / 1000000);
			deltaCount = 0;
		}
	}

	/**
	 * F.
	 * 
	 * @param l
	 *            the l
	 * @return the string
	 */
	private String f(long l) {
		return f(l, -1, "");
	}

	/**
	 * F.
	 * 
	 * @param l
	 *            the l
	 * @param percision
	 *            the percision
	 * @return the string
	 */
	@SuppressWarnings("unused")
	private String f(long l, int percision) {
		return f(l, percision, "");
	}

	/**
	 * F.
	 * 
	 * @param l
	 *            the l
	 * @param percision
	 *            the percision
	 * @param post
	 *            the post
	 * @return the string
	 */
	private String f(long l, int percision, String post) {
		String u = "";
		double v = l;
		int p = 0;
		if (l > Units.TEBIBYTE) {
			u = "t";
			v /= Units.TEBIBYTE;
			p = 4;
		} else if (l > Units.GIGIBYTE) {
			u = "g";
			v /= Units.GIGIBYTE;
			p = 2;
		} else if (l > Units.MEBIBYTE) {
			u = "m";
			v /= Units.MEBIBYTE;
			p = 1;
		} else if (l > Units.KIBIBYTE) {
			u = "k";
			v /= Units.KIBIBYTE;
			p = 0;
		} else {
			p = 0;
		}

		if (percision != -1) {
			p = percision;
		}

		String f = String.format("%%.%df%%s%%s", p);

		return String.format(f, v, u, post);
	}

	/**
	 * Fb.
	 * 
	 * @param l
	 *            the l
	 * @return the string
	 */
	private String fb(long l) {
		return f(l, -1, "b");
	}

	/**
	 * Fb.
	 * 
	 * @param l
	 *            the l
	 * @param percision
	 *            the percision
	 * @return the string
	 */
	private String fb(long l, int percision) {
		return f(l, percision, "b");
	}

	/**
	 * Gets the cleanup thread timeout.
	 * 
	 * @return the cleanup thread timeout
	 */
	public long getCleanupThreadTimeout() {
		return cleanupTimeout.get();
	}

	/**
	 * Makes sure that JVM GC is not invoked more then a certain timeout value
	 * since the last time it was invoked. Avoids too many JVM GC invocation
	 * calls that might overlap
	 * 
	 * @return true if JVM GC was invoked, otherwise false
	 */
	private boolean invokeSystemGC() {

		if ((System.currentTimeMillis() - lastSystemGCInvoke) < MIN_SYSTEM_GC_INVOKE_TIMEOUT) {
			return false;
		}

		if (vverbose) {
			logSystemGC();
		}

		System.gc();
		lastSystemGCInvoke = System.currentTimeMillis();
		firstSystemGCNeeded = 0;

		return true;
	}

	/*
	 * private long systemMinorGC() {
	 * 
	 * final long timestamp = System.currentTimeMillis(); Marker marker = new
	 * Marker(timestamp); // Now we wait for Marker to be
	 * 
	 * filler = 1;
	 * 
	 * while (true) { final Marker mark = (Marker) markerQueue.poll();
	 * 
	 * if (mark == marker) { while (markerQueue.poll() != null) { ; // Drain the
	 * queue quickly } break; } else {
	 * 
	 * filler++; new Object() { };
	 * 
	 * // Thread.yield(); try { if (filler % 10000 == 0) { Thread.sleep(1); } }
	 * catch (InterruptedException e) { } } }
	 * 
	 * return filler;
	 * 
	 * }
	 */
	/**
	 * Invoke system gc and wait.
	 */
	public synchronized void invokeSystemGCAndWait() {

		long ts = System.currentTimeMillis();
		long low = JMemory.availableDirectMemory();

		try {
			if (isCleanupThreadActive()) {
				memorySemaphore.acquire(memorySemaphore.availablePermits());
				memorySemaphore.tryAcquire(MIN_MEMORY_RELEASE,
						OUT_OF_MEMORY_TIMEOUT,
						TimeUnit.MILLISECONDS);
			} else {
				invokeSystemGC();
				drainRefQueue(OUT_OF_MEMORY_TIMEOUT);
			}
		} catch (IllegalArgumentException e) {
		} catch (InterruptedException e) {
		}

		 memorySemaphore.drainPermits();
		 memorySemaphore.release(DisposableGC.MIN_MEMORY_RELEASE);

		if (vverbose) {
			System.out.printf("DisposableGC: waiting for System.gc to finish:"
					+ " %dms, freed=%dMbytes%n",
					(System.currentTimeMillis() - ts),
					(JMemory.availableDirectMemory() - low) / (1024 * 1024));
		}
	}

	/**
	 * Issues a JVM GC request, while injecting a marker reference to be cleaned
	 * up by the very same JVM GC run. Until our marker reference is not cleaned
	 * up, we do not issue another JVM GC since this means that previous GC run
	 * has not reached our marker reference yet.
	 */
	public synchronized void invokeSystemGCWithMarker() {

		if (markerReference != null && markerReference.get() != null
				|| !isSystemGCReady()) {
			return;
		}

		if (vvverbose) {
			logMarker();
		}
		markerReference = new WeakReference<Object>(new Object() {
		});
		invokeSystemGC();
	}

	/**
	 * Checks if is cleanup complete.
	 * 
	 * @return true, if is cleanup complete
	 */
	public boolean isCleanupComplete() {
		synchronized (g0) {
			return g0.isEmpty();
		}
	}

	/**
	 * Checks if is cleanup thread active.
	 * 
	 * @return true, if is cleanup thread active
	 */
	public boolean isCleanupThreadActive() {
		return cleanupThreadActive.get() && cleanupThread.isAlive();
	}

	/**
	 * Checks if JVM GC can be called upon, at this particular time. If the
	 * previous invocation of JVM GC was less then minimum delay between
	 * consecutive calls, this function returns false.
	 * 
	 * @return true if JVM GC can be invoked at this time, otherwise false
	 */
	private final boolean isSystemGCReady() {
		if (firstSystemGCNeeded == 0) {
			firstSystemGCNeeded = System.currentTimeMillis();
		}

		return cleanupThreadProcessing.get() == false
				&& (System.currentTimeMillis() - lastSystemGCInvoke) > MIN_SYSTEM_GC_INVOKE_TIMEOUT;
	}

	/**
	 * Checks if is verbose.
	 * 
	 * @return the verbose
	 */
	public boolean isVerbose() {
		return verbose;
	}

	/**
	 * Checks if is v verbose.
	 * 
	 * @return the vverbose
	 */
	public boolean isVVerbose() {
		return vverbose;
	}

	/**
	 * Checks if is vV verbose.
	 * 
	 * @return the vvverbose
	 */
	public boolean isVVVerbose() {
		return vvverbose;
	}

	/**
	 * Log busy.
	 */
	private void logBusy() {
		System.out.printf("DisposableGC: busy%n");
	}

	/**
	 * Log finished.
	 */
	private void logFinished() {
		System.out.printf("DisposableGC: finished%n");
	}

	/**
	 * Log idle.
	 */
	private void logIdle() {
		System.out.printf("DisposableGC: idle - "
				+ "waiting for system GC to collect more objects%n");

	}

	/**
	 * Log limits.
	 */
	private void logLimits() {
		System.out
				.printf("DisposableGC: current native memory allocation limits are max=%s, soft=%s%n",
						fb(JMemory.maxDirectMemory()),
						fb(JMemory.softDirectMemory()));

	}

	/**
	 * Log marker.
	 */
	private void logMarker() {
		long ts = System.currentTimeMillis();
		long fs = ts - (ts / 1000) * 1000;

		/*
		 * Provide TS to fraction of a second in millis
		 */
		System.out.printf("DisposableGC: soft limit breached, "
				+ "issued a marker at %s.%d, minimum delay=%dms%n",
				new Time(ts),
				fs,
				MIN_SYSTEM_GC_INVOKE_TIMEOUT);

	}

	/**
	 * Log system gc.
	 */
	private void logSystemGC() {
		long ts = System.currentTimeMillis();
		long fs = ts - (ts / 1000) * 1000;
		long waited = ts - firstSystemGCNeeded;

		System.out
				.printf("DisposableGC: issued JVM GC request %s.%d waited=%dms (reserved=%s, available=%s)%n",
						new Time(ts),
						fs,
						waited,
						fb(JMemory.reservedDirectMemory()),
						fb(JMemory.availableDirectMemory()));

	}

	/**
	 * Log usage.
	 */
	private void logUsage() {
		System.out
				.printf("DisposableGC: [immediate=%3s(%4s)] [total=%3s(%7s), sem=%s] "
						+ "[gens: 0sec=%3s(%6s),10sec=%3s(%6s),60sec=%3s(%6s)]=%6s%n",
						f(deltaCount),
						fb(deltaSize, 0),
						f(totalDisposed),
						fb(totalSize),
						f(memorySemaphore.availablePermits()),
						f(g0.size()),
						fb(mem(g0)),
						f(g10.size()),
						fb(mem(g10)),
						f(g60.size()),
						fb(mem(g60)),
						fb(memoryHeldInRefCollection()));

	}

	/**
	 * Memory held in ref collection.
	 * 
	 * @return the long
	 */
	private long memoryHeldInRefCollection() {
		long size = 0;

		size += mem(g0);
		size += mem(g10);
		size += mem(g60);

		return size;
	}

	/**
	 * Sets the cleanup thread timeout.
	 * 
	 * @param timeout
	 *            the new cleanup thread timeout
	 */
	public void setCleanupThreadTimeout(long timeout) {
		cleanupTimeout.set(timeout);
	}

	/**
	 * Sets the verbose.
	 * 
	 * @param verbose
	 *            the verbose to set
	 */
	public void setVerbose(boolean verbose) {
		this.verbose = verbose;

		if (!verbose) {
			setVVerbose(false);
			setVVVerbose(false);
		} else {
			logLimits();
		}

	}

	/**
	 * Sets the v verbose.
	 * 
	 * @param vverbose
	 *            the vverbose to set
	 */
	public void setVVerbose(boolean vverbose) {
		if (vverbose) {
			setVerbose(true);
		} else {
			setVVVerbose(false);
		}

		this.vverbose = vverbose;
	}

	/**
	 * Sets the vV verbose.
	 * 
	 * @param vvverbose
	 *            the vvverbose to set
	 */
	public void setVVVerbose(boolean vvverbose) {
		if (vvverbose) {
			setVVerbose(true);
		}
		this.vvverbose = vvverbose;
	}

	/**
	 * Sort generations.
	 */
	private void sortGenerations() {
		final long ct = System.currentTimeMillis();

		/*
		 * Check for G60(64 second) old generation
		 */
		for (DisposableReference ref : this.g10) {
			if ((ct - ref.getTs()) > G60) {
				g10.remove(ref);
				g60.add(ref);
			} else {
				break;
			}
		}

		/*
		 * Check for G10 (10 second) old generation
		 */
		for (DisposableReference ref : this.g0) {
			if ((ct - ref.getTs()) > G10) {
				g0.remove(ref);
				g10.add(ref);

				// System.out.printf("DisposableGC:: %s%n", ref);
			} else {
				break;
			}
			// System.out.printf("DisposableGC:: delta=%d%n", (ct -
			// ref.getTs()));
		}
	}

	/**
	 * Start cleanup thread.
	 */
	public synchronized void startCleanupThread() {
		if (isCleanupThreadActive()) {
			return;
		}

		cleanupThread = new Thread(new Runnable() {

			public void run() {
				try {
					drainRefQueueLoop();

				} catch (InterruptedException e) {
					UncaughtExceptionHandler handler;
					handler = Thread.getDefaultUncaughtExceptionHandler();
					handler.uncaughtException(Thread.currentThread(), e);

				} finally {
					cleanupThreadActive.set(false);
					cleanupThread = null;

					synchronized (this) {
						notifyAll();
					}
				}
			}

		}, "DisposableGC");

		cleanupThreadActive.set(true);

		cleanupThread.setDaemon(true);
		cleanupThread.setPriority(cleanupThread.getPriority() - 1); // Lower
		// priority
		cleanupThread.start();
	}

	/**
	 * Stop cleanup thread.
	 * 
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	public void stopCleanupThread() throws InterruptedException {
		if (isCleanupThreadActive()) {
			synchronized (cleanupThread) {
				cleanupThreadActive.set(false);

				if (cleanupThread != null) {
					cleanupThread.wait();
				}
			}
		}
	}

	/**
	 * Wait for forcable cleanup.
	 * 
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	public void waitForForcableCleanup() throws InterruptedException {
		System.gc();
		while (waitForFullCleanup(5 * 1000) == false) {
			if (verbose && !cleanupThreadProcessing.get()) {
				// System.out.printf("DisposableGC: waiting on %d elements%n",
				// g0.size());
				for (int i = 0; i < g0.size(); i++) {
					DisposableReference o = g0.get(i);
					if (o != null && o.get() != null) {
						// System.out.printf("DisposableGC:#%d: %s%n", i,
						// o.get());
					}
				}
			}
		}

	}

	/**
	 * Wait for forcable cleanup.
	 * 
	 * @param timeout
	 *            the timeout
	 * @return true, if successful
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	public boolean waitForForcableCleanup(long timeout)
			throws InterruptedException {
		int count = (int) (timeout / 100) + 1;
		while ((count-- >= 0) && waitForFullCleanup(100) == false) {
			invokeSystemGC();
		}

		return isCleanupComplete();
	}

	/**
	 * Wait for full cleanup.
	 * 
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	public void waitForFullCleanup() throws InterruptedException {

		synchronized (g0) {
			while (g0.isEmpty() == false) {
				if (isCleanupThreadActive()) {
					g0.wait();
				} else {
					drainRefQueue();
				}
			}
		}
	}

	/**
	 * Wait for full cleanup.
	 * 
	 * @param timeout
	 *            the timeout
	 * @return true, if successful
	 * @throws InterruptedException
	 *             the interrupted exception
	 */
	public boolean waitForFullCleanup(long timeout) throws InterruptedException {

		synchronized (g0) {
			if (g0.isEmpty() == false) {
				if (isCleanupThreadActive()) {
					g0.wait(timeout);
				} else {
					drainRefQueue();
					if (g0.isEmpty() == false) {
						Thread.sleep(timeout);
						drainRefQueue();
					}
				}
			}

			return g0.isEmpty();
		}
	}
}
