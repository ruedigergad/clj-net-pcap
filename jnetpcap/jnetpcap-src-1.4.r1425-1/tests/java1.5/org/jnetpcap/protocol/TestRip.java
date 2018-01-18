/**
 *  All code (c)2012 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap.protocol;

import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.protocol.network.Rip1;
import org.junit.Test;

/**
 * 
 * @author Sly Technologies Inc.
 */
@SuppressWarnings("unused")
public class TestRip {

	@Test
	public void test() throws RegistryHeaderErrors {
		JRegistry.register(Rip1.class);
		Rip1 r1 = new Rip1();	
	}

}
