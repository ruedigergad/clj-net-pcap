/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap.extension;

import java.util.concurrent.TimeUnit;

import org.jnetpcap.JHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;

/**
 * Base abstract class for implementation of new capture extensions.
 *
 * @author Sly Technologies Inc.
 * @param <H>
 *            the generic handler type associated to this capture implementation
 * @param <T>
 *            the generic user data type passed to the handler
 */
public abstract class AbstractJCapture<H extends JHandler<T>, T> implements JCapture<H, T>, JExtension {

	/** The pcap. */
	private PcapExtension pcap;
	private boolean breakCapture;

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.extension.JExtension#setPcap(org.jnetpcap.Pcap)
	 */
	@Override
	public final void setPcap(Pcap pcap) {
		if (this.pcap != null && this.pcap != pcap) {
			throw new IllegalArgumentException("pcap already set");
		}

		this.pcap = PcapExtension.from(pcap);
	}

	/**
	 * Gets the pcap.
	 *
	 * @return the pcap
	 */
	protected PcapExtension getPcap() {
		return this.pcap;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.extension.JCapture#breakCapture()
	 */
	@Override
	public synchronized void breakCapture() {
		this.breakCapture = true;
	}

	/**
	 * Checks if is break capture.
	 *
	 * @return true, if is break capture
	 */
	protected boolean isBreakCapture() {
		return this.breakCapture;
	}

	/**
	 * Do capture.
	 *
	 * @param cnt
	 *            the cnt
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param timeout
	 *            the timeout
	 * @param unit
	 *            the unit
	 * @return the long
	 */
	protected abstract long doCapture(int cnt, H handler, T user, long timeout, TimeUnit unit);

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.extension.JCapture#capture(int, org.jnetpcap.JHandler,
	 *      java.lang.Object)
	 */
	public final long capture(int cnt, H handler, T user) {
		return doCapture(cnt, handler, user, 0, TimeUnit.MILLISECONDS);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.extension.JCapture#capture(org.jnetpcap.JHandler,
	 *      java.lang.Object)
	 */
	public final long capture(H handler, T user) {
		return doCapture(0, handler, user, 0, TimeUnit.MILLISECONDS);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.extension.JCapture#capture(int, org.jnetpcap.JHandler,
	 *      java.lang.Object, long, java.util.concurrent.TimeUnit)
	 */
	public final long capture(int cnt, H handler, T user, long timeout, TimeUnit unit) {
		return doCapture(cnt, handler, user, timeout, unit);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.extension.JCapture#capture(org.jnetpcap.JHandler,
	 *      java.lang.Object, long, java.util.concurrent.TimeUnit)
	 */
	public final long capture(H handler, T user, long timeout, TimeUnit unit) {
		return doCapture(0, handler, user, timeout, unit);
	}
}
