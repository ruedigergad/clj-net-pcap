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
package org.jnetpcap.bugs;

import java.io.File;
import java.io.FilenameFilter;

import org.hyperic.sigar.ProcMem;
import org.hyperic.sigar.Sigar;
import org.hyperic.sigar.SigarException;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapUtils;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class Bug2847124_jbytebuffer_handler_memory_leak.
 */
public class Bug2847124_jbytebuffer_handler_memory_leak
    extends
    TestUtils {

	/** The Constant DIR. */
	private final static File DIR = new File("tests");

	/** The Constant COUNT. */
	private static final int COUNT = 10;

	/** The errbuf. */
	private StringBuilder errbuf;

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		errbuf = new StringBuilder();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		errbuf = null;
	}

	/** The b. */
	int b = 0;

	/** The bytes. */
	int bytes = 0;

	/** The h. */
	int h = 0;

	/** The headers. */
	int headers = 0;

	/** The total. */
	int total = 0;

	/** The start. */
	long start = 0;

	/** The end. */
	long end = 0;

	/** The count. */
	int count = 0;

	/** The ts. */
	long ts = 0;

	/** The te. */
	long te = 0;

	/**
	 * Test inject test j packet handler.
	 * 
	 * @throws SigarException
	 *           the sigar exception
	 */
	public void testInjectTestJPacketHandler() throws SigarException {

		start = ts = System.currentTimeMillis();
		Sigar sig = new Sigar();
		long pid = sig.getPid();
		ProcMem pm = new ProcMem();
		long base = 0;

		final JBuffer buf =
		    new JBuffer(FormatUtils.toByteArray(""
		        + "0007e914 78a20010 7b812445 080045c0"
		        + "00280005 0000ff11 70e7c0a8 62dec0a8"
		        + "65e906a5 06a50014 e04ac802 000c0002"
		        + "00000002 00060000 00000000"
		        
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//
//		        
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
//		        + "00000002 00060000 00000000 00000000"
		        
		    ));
		final PcapHeader header = new PcapHeader(buf.size(), buf.size());
		PcapPacket packet = new PcapPacket(header, buf);
		
		System.out.printf("injected packet size=%d bytes\n", buf.size());

		for (int i = 0; i < COUNT; i++) {
			PcapUtils.injectLoop(10000, JProtocol.ETHERNET_ID,
			    new PcapPacketHandler<String>() {

				    public void nextPacket(PcapPacket packet, String user) {
					    assertNotNull(packet);

					    count++;
					    b += packet.size();
					    h += packet.getState().getHeaderCount();

				    }

			    }, "", packet);

			/*
			 * Skip 1 iteration to allow all the files to be opened and any allocated
			 * resources to end up as a memory base.
			 */
			if (i == 0) {
				base = pm.getSize();
			}

			if (i % (COUNT / 10) == 0 && i != 0) {
				te = System.currentTimeMillis();
				total += count;
				bytes += b;
				headers += h;
				double delta = ((double) te - (double) ts) / 1000.;

				pm.gather(sig, pid);

				System.out.printf(
				    "tot=%.1f packets=%d pps=%.0f bytes=%.0fKb/s hdr=%.0f/s "
				        + "hdr=%.0fus rm=%dKb pm=%.1fb vm=%dKb\n",
				    ((double) total) / 1024 / 1024, count, ((double) count / delta),
				    ((double) b / delta / 1024.), ((double) h / delta),
				    1000000. / ((double) h / delta), pm.getResident() / (1024),
				    ((double) pm.getResident() - base) / count, pm.getSize() / (1024));
				System.out.flush();

				ts = te;
				count = 0;
				b = 0;
				h = 0;
			}

			if (i % (COUNT / 10) == 0 && i != 0) {
				System.out.println("GC()");
				System.gc();
			}

		}

		end = System.currentTimeMillis();
		double delta = ((double) end - (double) start) / 1000.;
		System.out
		    .printf(
		        "totals: packets=%d average=%f pps bytes=%fKb/s headers=%f/s header_scan=%fus\n",
		        count, ((double) total / delta), ((double) bytes / delta / 1024.),
		        ((double) h / delta), 1000000. / ((double) h / delta));
		System.out.flush();

	}

	/**
	 * Test stress test j packet handler.
	 * 
	 * @throws SigarException
	 *           the sigar exception
	 */
	public void testStressTestJPacketHandler() throws SigarException {
		String[] files = DIR.list(new FilenameFilter() {

			public boolean accept(File dir, String name) {
				return name.equals("test-sip-rtp-g711.pcap");
			}

		});

		start = ts = System.currentTimeMillis();
		Sigar sig = new Sigar();
		long pid = sig.getPid();
		ProcMem pm = new ProcMem();
		long base = 0;

		for (int i = 0; i < COUNT; i++) {

			for (final String fname : files) {
				Pcap pcap = Pcap.openOffline(DIR.toString() + "/" + fname, errbuf);
				assertNotNull(errbuf.toString(), pcap);

				pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<Pcap>() {

					public void nextPacket(JPacket packet, Pcap user) {
						assertNotNull(packet);

						count++;
						b += packet.size();
						// h += packet.getState().getHeaderCount();

					}

				}, pcap);

				pcap.close();
			}

			/*
			 * Skip 1 iteration to allow all the files to be opened and any allocated
			 * resources to end up as a memory base.
			 */
			if (i == 0) {
				base = pm.getSize();
			}

			if (i % (COUNT / 10) == 0 && i != 0) {
				te = System.currentTimeMillis();
				total += count;
				bytes += b;
				headers += h;
				double delta = ((double) te - (double) ts) / 1000.;

				pm.gather(sig, pid);

				System.out.printf(
				    "tot=%.1f packets=%d pps=%.0f bytes=%.0fKb/s hdr=%.0f/s "
				        + "hdr=%.0fus rm=%dKb pm=%.1fb vm=%dKb\n",
				    ((double) total) / 1024 / 1024, count, ((double) count / delta),
				    ((double) b / delta / 1024.), ((double) h / delta),
				    1000000. / ((double) h / delta), pm.getResident() / (1024),
				    ((double) pm.getResident() - base) / count, pm.getSize() / (1024));
				System.out.flush();

				ts = te;
				count = 0;
				b = 0;
				h = 0;
			}

			if (i % (COUNT / 10) == 0 && i != 0) {
				System.out.println("GC()");
				System.gc();
			}

		}

		end = System.currentTimeMillis();
		double delta = ((double) end - (double) start) / 1000.;
		System.out
		    .printf(
		        "totals: packets=%d average=%f pps bytes=%fKb/s headers=%f/s header_scan=%fus\n",
		        count, ((double) total / delta), ((double) bytes / delta / 1024.),
		        ((double) h / delta), 1000000. / ((double) h / delta));
		System.out.flush();

	}

	/**
	 * Test stress test pcap packet handler.
	 */
	public void testStressTestPcapPacketHandler() {
		String[] files = DIR.list(new FilenameFilter() {

			public boolean accept(File dir, String name) {
				return name.endsWith(".pcap");
			}

		});

		for (int i = 0; i < COUNT; i++) {
			for (String fname : files) {
				Pcap pcap = Pcap.openOffline(DIR.toString() + "/" + fname, errbuf);
				assertNotNull(errbuf.toString(), pcap);

				pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<Pcap>() {

					public void nextPacket(PcapPacket packet, Pcap user) {
						assertNotNull(packet);

					}

				}, pcap);

				pcap.close();
			}

			System.out.printf(".");
			System.out.flush();
		}

		System.out.println();
	}

	/**
	 * Test stress test j buffer handler.
	 * 
	 * @throws SigarException
	 *           the sigar exception
	 */
	public void testStressTestJBufferHandler() throws SigarException {
		String[] files = DIR.list(new FilenameFilter() {

			public boolean accept(File dir, String name) {
				return name.endsWith(".pcap");
			}

		});

		start = ts = System.currentTimeMillis();
		Sigar sig = new Sigar();
		long pid = sig.getPid();
		ProcMem pm = new ProcMem();
		long base = 0;

		for (int i = 0; i < COUNT; i++) {
			for (final String fname : files) {
				Pcap pcap = Pcap.openOffline(DIR.toString() + "/" + fname, errbuf);
				assertNotNull(errbuf.toString(), pcap);

				pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {

					public void nextPacket(PcapHeader header, JBuffer buffer, Pcap user) {
						count++;
						b += buffer.size();
					}

				}, pcap);

				pcap.close();
			}

			/*
			 * Skip 1 iteration to allow all the files to be opened and any allocated
			 * resources to end up as a memory base.
			 */
			if (i == 0) {
				base = pm.getSize();
			}

			if (i % (COUNT / 10) == 0 && i != 0) {
				te = System.currentTimeMillis();
				total += count;
				bytes += b;
				headers += h;
				double delta = ((double) te - (double) ts) / 1000.;

				pm.gather(sig, pid);

				System.out.printf(
				    "tot=%.1fMp packets=%d pps=%.0f bytes=%.0fKb/s hdr=%.0f/s "
				        + "hdr=%.0fus rm=%dKb pm=%.1fb vm=%dKb\n",
				    ((double) total) / 1024 / 1024, count, ((double) count / delta),
				    ((double) b / delta / 1024.), ((double) h / delta),
				    1000000. / ((double) h / delta), pm.getResident() / (1024),
				    ((double) pm.getResident() - base) / count, pm.getSize() / (1024));
				System.out.flush();

				ts = te;
				count = 0;
				b = 0;
				h = 0;
			}
		}

		end = System.currentTimeMillis();
		double delta = ((double) end - (double) start) / 1000.;
		System.out
		    .printf(
		        "totals: packets=%d average=%f pps bytes=%fKb/s headers=%f/s header_scan=%fus\n",
		        count, ((double) total / delta), ((double) bytes / delta / 1024.),
		        ((double) h / delta), 1000000. / ((double) h / delta));
		System.out.flush();

	}

}
