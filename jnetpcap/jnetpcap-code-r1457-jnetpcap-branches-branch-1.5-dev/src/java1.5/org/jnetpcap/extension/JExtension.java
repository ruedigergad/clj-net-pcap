/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap.extension;

import org.jnetpcap.Pcap;

/**
 * An interface for all jNetPcap extensions to implement.
 * 
 * @author Sly Technologies Inc.
 */
public interface JExtension {

	/**
	 * Sets the pcap.
	 *
	 * @param pcap
	 *            the new pcap
	 */
	public void setPcap(Pcap pcap);
}
