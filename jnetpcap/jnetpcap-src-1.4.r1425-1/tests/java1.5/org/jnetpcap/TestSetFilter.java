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

import java.nio.ByteBuffer;
import java.util.Date;

// TODO: Auto-generated Javadoc
/**
 * The Class TestSetFilter.
 */
@SuppressWarnings("deprecation")
public class TestSetFilter {

	/** The fname. */
	private static String fname = "tests/test-l2tp.pcap";
	
	/**
	 * The main method.
	 * 
	 * @param args
	 *          the arguments
	 */
	public static void main(String[] args) {


		PcapBpfProgram bpf = new PcapBpfProgram();
                String str = "host 192.168.101";
		StringBuilder errbuf = new StringBuilder();

                System.out.println("trying to compiler the filter() OK\n"); System.out.flush();
                Pcap pcap = Pcap.openOffline(fname, errbuf);
                System.out.println("filter was compiled OK\n"); System.out.flush();

                @SuppressWarnings("unused")
                int r = pcap.compile(bpf, str, 0, 0);
                System.out.println("err=" + pcap.getErr());

                PcapHandler<String> handler = new PcapHandler<String>() {
                        public void nextPacket(String user, long seconds, int useconds,
                            int caplen, int len, ByteBuffer buffer) {

                                 System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
                                 .toString(), new Date(seconds * 1000).toString(), caplen, len,
                                 buffer.capacity());
                        }
                };

                System.out.println("trying to set the filter() OK\n"); System.out.flush();
                pcap.setFilter(bpf);
                System.out.println("filter was set OK\n"); System.out.flush();
                pcap.loop(10, handler, str);

                System.out.println("trying to free the filter() OK\n"); System.out.flush();
                Pcap.freecode(bpf);
                System.out.println("filter was freed OK\n"); System.out.flush();

                pcap.close();
		
	}
}
