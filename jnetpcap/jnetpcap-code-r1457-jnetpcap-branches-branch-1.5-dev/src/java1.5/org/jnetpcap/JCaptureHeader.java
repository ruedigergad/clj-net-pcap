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
 * Interface to to capture header provided by the capturing library. For example
 * <code>PcapHeader</code>, the capture header provided by libpcap,
 * implements this interface which provides access to minimum set of information
 * about the capture packet.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JCaptureHeader {

	/**
	 * Retrieves the length of the packet that was actually captured. This could
	 * be only a portion of the original packet if snaplen filter was set during
	 * Pcap.openXXX call. If the packet was not trucated, this length should equal
	 * the length returned by {@link #wirelen()}.
	 * 
	 * @return length in bytes
	 */
	public abstract int caplen();

	/**
	 * Retrieves the length of the packet before any of it was truncated by the
	 * capture mechanism. This is the size of the orignal packet as it was send
	 * accross the network.
	 * 
	 * @return length in bytes
	 */
	public abstract int wirelen();

	/**
	 * Capture timestamp in UNIX seconds.
	 * 
	 * @return timestamp in seconds since 1970
	 */
	public abstract long seconds();

	/**
	 * Fractional part of the second when the packet was captured. If the
	 * resolution of the original capture timestamp is lower than nano seconds,
	 * they are converted to nano seconds. For example of the capture timestamp is
	 * in micro seconds, then the micro seconds fraction is multiplied by a 1000
	 * before being returned to conform to nano second return timestamp.
	 * 
	 * @return Number of nano seconds at the time of the packet capture. The valid
	 *         value returned by this method is from 0 to 999,999,999.
	 */
	public abstract long nanos();

	/**
	 * Converts the timestamp into a java style timestamp suitable for usage with
	 * <code>Date</code> class.
	 * 
	 * @return capture timestamp in milli-seconds
	 */
	public abstract long timestampInMillis();

	/**
	 * Gets the absolute capture timestamp in nano seconds (10e-9).
	 * 
	 * @return timestamp in nano seconds
	 */
	public abstract long timestampInNanos();

	/**
	 * Gets the absolute capture timestam pin micro seconds (10e-6).
	 * 
	 * @return timestamp in micro seconds
	 */
	public abstract long timestampInMicros();

	/**
	 * Seconds.
	 * 
	 * @param seconds
	 *          the seconds
	 */
	public abstract void seconds(long seconds);

	/**
	 * Nanos.
	 * 
	 * @param nanos
	 *          the nanos
	 */
	public abstract void nanos(long nanos);

	/**
	 * Caplen.
	 * 
	 * @param caplen
	 *          the caplen
	 */
	public abstract void caplen(int caplen);

	/**
	 * Wirelen.
	 * 
	 * @param wirelen
	 *          the wirelen
	 */
	public abstract void wirelen(int wirelen);

	/**
	 * Inits the from.
	 * 
	 * @param captureHeader
	 *          the capture header
	 */
	public abstract void initFrom(JCaptureHeader captureHeader);
}
