/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap.extension;

import java.util.concurrent.TimeUnit;

import org.jnetpcap.JHandler;

/**
 * Interface used to abstract pcap callback method. JCapture is used to extend
 * pcap with new callback implementations and supporting capture functionality.
 *
 * @author Sly Technologies Inc.
 * @param <H>
 *            the generic type
 * @param <T>
 *            the generic type
 */
public interface JCapture<H extends JHandler<T>, T> extends JExtension {

	/**
	 * Capture.
	 *
	 * @param cnt
	 *            the cnt
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @return the long
	 */
	public long capture(int cnt, H handler, T user);

	/**
	 * Capture.
	 *
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @return the long
	 */
	public long capture(H handler, T user);

	/**
	 * Break capture.
	 */
	public void breakCapture();

	/**
	 * Capture.
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
	public long capture(int cnt, H handler, T user, long timeout, TimeUnit unit);

	/**
	 * Capture.
	 *
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
	public long capture(H handler, T user, long timeout, TimeUnit unit);
}
