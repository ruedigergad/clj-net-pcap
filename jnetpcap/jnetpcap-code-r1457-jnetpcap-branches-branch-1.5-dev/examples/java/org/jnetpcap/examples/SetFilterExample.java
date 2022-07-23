/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.jnetpcap.examples;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class SetFilterExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		StringBuilder errbuf = new StringBuilder();
		String fname = "tests/test-afs.pcap"; 
		
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return;
		}
		
		PcapBpfProgram program = new PcapBpfProgram();
		String expression = "host 192.168.1.1";
		int optimize = 0;         // 0 = false
		int netmask = 0xFFFFFF00; // 255.255.255.0
		
		if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
			System.err.println(pcap.getErr());
			return;
		}
		
		if (pcap.setFilter(program) != Pcap.OK) {
			System.err.println(pcap.getErr());
			return;		
		}
		
		System.out.println("Filter set !!! : " + expression);
		
		pcap.close();

	}

}
