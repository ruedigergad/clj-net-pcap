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
package org.jnetpcap.packet;

import java.io.File;
import java.io.FilenameFilter;
import java.lang.ref.ReferenceQueue;
import java.nio.ByteBuffer;
import java.sql.Time;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.hyperic.sigar.ProcMem;
import org.hyperic.sigar.Sigar;
import org.hyperic.sigar.SigarException;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapUtils;
import org.jnetpcap.nio.DisposableGC;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Tcp;

// TODO: Auto-generated Javadoc
/**
 * The Class TestForMemoryLeaks.
 */
@SuppressWarnings("unused")
public class TestForMemoryLeaks extends TestUtils {

	/** The Constant DIR. */
	private final static File DIR = new File("tests");

	/** The Constant PEER_1S. */
	private static final int PEER_1S = 401; // 0:0:1

	/** The Constant PEER_1M. */
	private static final int PEER_1M = 60 * PEER_1S; // 0:1:0

	/** The Constant PEER_1H. */
	private static final int PEER_1H = 60 * PEER_1M; // 1:0:0

	/** The Constant PEER_3M_35S. */
	private static final int PEER_3M_35S = 9000; // 3:35

	/** The Constant TCP_SCAN_TRANSFERTO_1S. */
	private static final int TCP_SCAN_TRANSFERTO_1S = 100; // 0:0:1

	/** The Constant TCP_SCAN_TRANSFERTO_1M. */
	private static final int TCP_SCAN_TRANSFERTO_1M = 60 * TCP_SCAN_TRANSFERTO_1S; // 0:0:1

	/** The Constant GENERAL_SCAN_TRANSFERTO_1S. */
	private static final int GENERAL_SCAN_TRANSFERTO_1S = 14; // 0:0:1

	/** The Constant GENERAL_SCAN_TRANSFERTO_1M. */
	private static final int GENERAL_SCAN_TRANSFERTO_1M =
			60 * GENERAL_SCAN_TRANSFERTO_1S; // 0:0:1

	/** The Constant GENERAL_SCAN_TRANSFERTO__Q_1S. */
	private static final int GENERAL_SCAN_TRANSFERTO__Q_1S = 12; // 0:0:1

	/** The Constant GENERAL_SCAN_TRANSFERTO_Q_1M. */
	private static final int GENERAL_SCAN_TRANSFERTO_Q_1M =
			60 * GENERAL_SCAN_TRANSFERTO__Q_1S; // 0:0:1

	/** The Constant COUNT. */
	private static final int COUNT = 2 * GENERAL_SCAN_TRANSFERTO_1M;

	/** The Constant LINES. */
	private static final int LINES = 10;

	/** The errbuf. */
	private StringBuilder errbuf;

	/** The G. */
	private final double G = (1024. * 1024. * 1024);

	/** The g. */
	private final double g = (1000. * 1000. * 1000);

	/** The M. */
	private final double M = (1024. * 1024.);

	/** The K. */
	private final double K = (1024.);

	/** The m. */
	private final double m = (1000. * 1000.);

	/** The k. */
	private final double k = (1000.);

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		errbuf = new StringBuilder();
		// System.out.println(System.getProperties());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		errbuf = null;
	}

	/** The b. */
	long b = 0;

	/** The bytes. */
	long bytes = 0;

	/** The h. */
	long h = 0;

	/** The headers. */
	long headers = 0;

	/** The total. */
	long total = 0;

	/** The start. */
	long start = 0;

	/** The end. */
	long end = 0;

	/** The count. */
	long count = 0;

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

				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				//
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				//
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				//
				//
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"
				// + "00000002 00060000 00000000 00000000"

						));
		final PcapHeader header = new PcapHeader(buf.size(), buf.size());
		PcapPacket packet = new PcapPacket(header, buf);

		System.out.printf("injected packet size=%d bytes\n", buf.size());

		for (int i = 0; i < COUNT; i++) {
			PcapUtils.injectLoop(1000,
					JProtocol.ETHERNET_ID,
					new PcapPacketHandler<String>() {

						public void nextPacket(PcapPacket packet, String user) {
							assertNotNull(packet);

							count++;
							b += packet.size();
							h += packet.getState().getHeaderCount();

						}

					},
					"",
					packet);

			/*
			 * Skip 1 iteration to allow all the files to be opened and any allocated
			 * resources to end up as a memory base.
			 */
			if (i == 0) {
				base = pm.getSize();
			}

			if (i % (COUNT / LINES) == 0 && i != 0) {
				te = System.currentTimeMillis();
				total += count;
				bytes += b;
				headers += h;
				double delta = ((double) te - (double) ts) / 1000.;

				pm.gather(sig, pid);

				System.out
						.printf("tot=%.1f packets=%d pps=%.0f bytes=%.0fKb/s hdr=%.0f/s "
								+ "hdr=%.0fus rm=%dKb pm=%.1fb vm=%dKb\n",
								((double) total) / 1024 / 1024,
								count,
								(count / delta),
								(b / delta / 1024.),
								(h / delta),
								1000000. / (h / delta),
								pm.getResident() / (1024),
								((double) pm.getResident() - base) / count,
								pm.getSize() / (1024));
				System.out.flush();

				ts = te;
				count = 0;
				b = 0;
				h = 0;
			}

			// if (i % (COUNT / 10) == 0 && i != 0) {
			// System.out.println("GC()");
			// System.gc();
			// }

		}

		end = System.currentTimeMillis();
		double delta = ((double) end - (double) start) / 1000.;
		System.out
				.printf("totals: packets=%d average=%f pps bytes=%fKb/s headers=%f/s header_scan=%fus\n",
						count,
						(total / delta),
						(bytes / delta / 1024.),
						(h / delta),
						1000000. / (h / delta));
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
						h += packet.getState().getHeaderCount();

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

			if (i % (COUNT / LINES) == 0 && i != 0) {
				te = System.currentTimeMillis();
				total += count;
				bytes += b;
				headers += h;
				double delta = ((double) te - (double) ts) / 1000.;

				pm.gather(sig, pid);

				System.out
						.printf("tot=%.1fMpkts packets=%d pps=%.0f bytes=%.0fKb/s hdr=%.0f/s "
								+ "hdr=%.0fus rm=%dKb pm=%.1fb vm=%dKb\n",
								((double) total) / (1000000),
								count,
								(count / delta),
								(b / delta / 1024.),
								(h / delta),
								1000000. / (h / delta),
								pm.getResident() / (1024),
								((double) pm.getResident() - base) / count,
								pm.getSize() / (1024));
				System.out.flush();

				ts = te;
				count = 0;
				b = 0;
				h = 0;
			}

			// if (i % (COUNT / 10) == 0 && i != 0) {
			// System.out.println("GC()");
			// System.gc();
			// }

		}

		end = System.currentTimeMillis();
		double delta = ((double) end - (double) start) / 1000.;
		System.out
				.printf("totals: packets=%d average=%f pps bytes=%fKb/s headers=%f/s header_scan=%fus\n",
						count,
						(total / delta),
						(bytes / delta / 1024.),
						(h / delta),
						1000000. / (h / delta));
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

		for (int i = 0; i < COUNT / 10; i++) {
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

			if ((i % 80) == 0) {
				System.out.println();
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
		final PcapPacket packet = new PcapPacket(JMemory.POINTER);
		int loop = 0;
		for (int i = 0; i < COUNT; i++) {
			for (final String fname : files) {
				Pcap pcap = Pcap.openOffline(DIR.toString() + "/" + fname, errbuf);
				assertNotNull(errbuf.toString(), pcap);

				pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {

					public void nextPacket(PcapHeader header, JBuffer buffer, Pcap user) {
						count++;
						b += buffer.size();

						packet.peerAndScan(Ethernet.ID, header, buffer);
						h += packet.getState().getHeaderCount();
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

			if (i % (COUNT / LINES) == 0 && i != 0) {
				loop++;
				te = System.currentTimeMillis();
				total += count;
				bytes += b;
				headers += h;
				double delta = ((double) te - (double) ts) / 1000.;

				pm.gather(sig, pid);

				System.out.printf("#%-2d %s: ",
						loop,
						new Time(System.currentTimeMillis()));
				System.out
						.printf("tot=%.1fMp packets=%d pps=%.0f bytes=%.0fMb/s hdr=%.0f/s "
								+ "hdr=%.0fus rm=%.1fMb pm=%.1fb vm=%dKb\n",
								((double) total) / 1000 / 1000, // Tot
								count, // packets
								(count / delta), // pps
								(b / delta / (1024. * 1024)), // bytes
								(h / delta), // hdr/s
								1000000. / (h / delta), // hdr us
								(double) pm.getResident() / (1024 * 1024), // rm
								((double) pm.getResident() - base) / count, // pm
								pm.getSize() / (1024)); // vm
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
				.printf("totals: packets=%d average=%f pps bytes=%fKb/s headers=%f/s header_scan=%fus\n",
						count,
						(total / delta),
						(bytes / delta / 1024.),
						(h / delta),
						1000000. / (h / delta));
		System.out.flush();

	}

	/**
	 * Test stress test j buffer handler from memory.
	 * 
	 * @throws SigarException
	 *           the sigar exception
	 */
	public void testStressTestJBufferHandlerFromMemory() throws SigarException {
		String[] files = getDirFileList(DIR, ".pcap");
		JPcapRecordBuffer buffer = loadAllPacketsFromFiles(files);
		final int packetCount = buffer.getInt(0);
		final int size = buffer.size();

		System.out.printf("Read %d files, with %d packets, for %d bytes\n",
				files.length,
				packetCount,
				size);

		start = ts = System.currentTimeMillis();
		Sigar sig = new Sigar();
		long pid = sig.getPid();
		ProcMem pm = new ProcMem();
		long base = 0;
		final PcapPacket packet = new PcapPacket(JMemory.POINTER);
		int loop = 0;
		final Tcp tcp = new Tcp();

		final JBufferHandler<Object> handler = new JBufferHandler<Object>() {

			public void nextPacket(PcapHeader header, JBuffer buffer, Object user) {

				packet.peerAndScan(Ethernet.ID, header, buffer);

				h += packet.getState().getHeaderCount();

				// if (packet.hasHeader(tcp)) {
				// System.out.printf("#%d: ", packet.getFrameNumber());
				// System.out.println(packet.toString());
				// }
			}

		};

		for (int i = 0; i < COUNT; i++) {
			b += size;
			count += buffer.dispatchToJBuffeHandler(handler, null);

			/*
			 * Skip 1 iteration to allow all the files to be opened and any allocated
			 * resources to end up as a memory base.
			 */
			if (i == 0) {
				base = pm.getSize();
			}

			// if (i % (COUNT / 10000) == 0 && i != 0) {
			// System.out.printf("=");
			// System.out.flush();
			// }

			if (i % (COUNT / LINES) == 0 && i != 0) {
				// System.out.println();

				loop++;
				te = System.currentTimeMillis();
				total += count;
				bytes += b;
				headers += h;
				double delta = ((double) te - (double) ts) / 1000.;
				double hps = (h / delta);
				double sph = 1000000000. / (h / delta);

				pm.gather(sig, pid);

				System.out.printf("#%-2d %s: ",
						loop,
						new Time(System.currentTimeMillis()));
				System.out.printf("tot=%.1fMp " + "packets=%d " + "pps=%.0f(%.1fus) "
						+ "hps=%.0f(%.0fns) " + "bytes=%.0fMb/s " + "rm=%.1fMb "
						+ "pm=%.1fb " + "vm=%dKb" + "%n",

				((double) total) / 1000 / 1000, // Tot
						count, // packets
						(count / delta), // pps
						delta * 1000000. / count,
						hps, // hdr/s
						((Double.isInfinite(sph)) ? 0.0 : sph), // hdr ns
						(b / delta / (1024. * 1024)), // bytes
						(double) pm.getResident() / (1024 * 1024), // rm
						((double) pm.getResident() - base) / count, // pm
						pm.getSize() / (1024)); // vm
				System.out.flush();

				ts = te;
				count = 0;
				b = 0;
				h = 0;
			}
		}
		// System.out.println();

		end = System.currentTimeMillis();
		double delta = ((double) end - (double) start) / 1000.;
		double hps = ((double) headers / 1000 / delta);
		double sph = 1000000000. / (headers / delta);

		long d = (end - start) / 1000;
		long seconds = (d % 60);
		long minutes = ((d / 60) % 60);
		long hours = ((d / 3600) % 24);

		System.out.printf("### %02d:%02d:%02d ", hours, minutes, seconds);
		System.out.printf("packets=%d(%.1fKpps, %.1fns/p) "
				+ "headers=%d(%.0fKhps, %.0fns/h) " + "MBps=%.3f(%.3fMbps) " + "%n",

				total,
				(total / delta / 1000),
				delta * 1000000000. / total,
				headers,
				hps,
				sph,
				(bytes / delta / (1024. * 1024)),
				((double) bytes * 8 / delta / (1024. * 1024)));
		System.out.flush();
	}

	/**
	 * Test stress test queued j buffer handler from memory.
	 * 
	 * @throws SigarException
	 *           the sigar exception
	 * @throws InterruptedException
	 *           the interrupted exception
	 */
	public void testStressTestQueuedJBufferHandlerFromMemory()
			throws SigarException, InterruptedException {
		String[] files = getDirFileList(DIR, ".pcap");
		JPcapRecordBuffer buffer = loadAllPacketsFromFiles(files);
		final int packetCount = buffer.getInt(0);
		final int size = buffer.size();

		System.out.printf("Read %d files, with %d packets, for %d bytes\n",
				files.length,
				packetCount,
				size);

		start = ts = System.currentTimeMillis();
		Sigar sig = new Sigar();
		long pid = sig.getPid();
		ProcMem pm = new ProcMem();
		long base = 0;

		final PcapPacket packet = new PcapPacket(JMemory.POINTER);
		final PcapPacket.State state = packet.getState();
		final Tcp tcp = new Tcp();
		// final TcpScanner tcpScanner = new TcpScanner();

		final ByteBuffer byteBuffer = ByteBuffer.allocate(8 * 1024);

		final ReferenceQueue<PcapPacket> refQueue =
				new ReferenceQueue<PcapPacket>();

		final TextFormatter out = new TextFormatter(DEV_NULL);

		// Thread.currentThread().setPriority(Thread.MAX_PRIORITY);
		Thread.currentThread().setPriority(Thread.NORM_PRIORITY);
		// Thread.currentThread().setPriority(Thread.MIN_PRIORITY);

		int loop = 0;

		// DisposableGC.getDeault().stopCleanupThread();
		DisposableGC.getDefault().startCleanupThread();

		// JPacket.setFormatter(new TextFormatter(DEV_NULL));

		final BlockingQueue<PcapPacket> queue =
				new LinkedBlockingQueue<PcapPacket>(10);
		final JBufferHandler<Object> handler = new JBufferHandler<Object>() {

			public void nextPacket(PcapHeader header, JBuffer buffer, Object user) {
				// final int size = buffer.size();

				// long index = total + count;
				// System.out.printf("#%d", index);

				b += buffer.size();
				PcapPacket pkt = new PcapPacket(header, buffer);
				// pkt.scan(Ethernet.ID);
				// h += pkt.getState().getHeaderCount();

				// if (queue.remainingCapacity() == 0) {
				// queue.clear();
				// }
				//
				// try {
				// queue.put(pkt);
				// } catch (InterruptedException e) {
				// }

				// packet.peer(header, buffer);

				// b += packet.transferHeaderAndDataFrom(header, buffer);
				// new Object(){};
				// tcpScanner.scan(buffer);
				// h += tcpScanner.getHCount();

				// if (tcpScanner.hasTcp()) {
				// final int offset = tcpScanner.tcpPayloadOffset();
				// final int length = tcpScanner.tcpPayloadLength();
				//
				// b += buffer.transferTo(byteBuffer, offset, length);
				// byteBuffer.clear();
				//
				// }
				// b += buffer.transferTo(byteBuffer, 0, size);
				// byteBuffer.clear();

				// packet.scan(Ethernet.ID);
				// packet.peerAndScan(Ethernet.ID, header, buffer);
				// try {out.format(packet);} catch (IOException e) {
				// e.printStackTrace();}
				// packet.peer(header, buffer);
				// state.getFrameNumber();
				// buffer.peer(packet);

				// b += size + header.size();
				count++;
				// h += packet.getState().getHeaderCount();

				// try {
				// if (count % 20 == 0) {
				// Thread.sleep(1);
				// }
				// } catch (InterruptedException e) {
				// }
			}

		};

		for (int i = 0; i < COUNT; i++) {
			buffer.dispatchToJBuffeHandler(handler, null);

			/*
			 * Skip 1 iteration to allow all the files to be opened and any allocated
			 * resources to end up as a memory base.
			 */
			if (i == 0) {
				base = pm.getResident();
			}

			// if (i % (COUNT / 10000) == 0 && i != 0) {
			// System.out.printf("=");
			// System.out.flush();
			// }

			if (i % (COUNT / LINES) == 0 && i != 0) {
				// System.out.println();

				loop++;
				te = System.currentTimeMillis();
				pm.gather(sig, pid);
				total += count;
				bytes += b;
				headers += h;
				double delta = ((double) te - (double) ts) / 1000.;
				double hps = (h / delta);
				double bps = ((double) b * 8 / delta);
				double sph = 1000000000. / (h / delta);
				sph = ((Double.isInfinite(sph)) ? 0.0 : sph);
				double rm = (pm.getResident() - base);
				double vm = (pm.getSize());

				System.out.printf("#%-2d %s: ",
						loop,
						new Time(System.currentTimeMillis()));
				System.out.printf("tot=%3.2fMp "
						+ /* "packets=%d " + */"Kpps=%.2f(%.2fns) " + /*
																													 * "hps=%.0f(%.0fns) "
																													 * +
																													 */"rate=%.2fMbps "
						+ "rm=%.2fMb "
						/* + "vm=%.2fMb" */
						+ "available=%.2fMb(%.2fMb) " + "%n",

				(total) / m, // Tot
						/* count, */// packets
						(count / delta / k), // pps
						delta * 1000000000. / count,
						/* hps / 1000, */// hdr/s
						/* sph, */// hdr ns
						bps / M, // bits per second
						rm / M // Resident Memory
						/* vm / M */,
						(JMemory.availableDirectMemory()) / M,
						(JMemory.maxDirectMemory()) / M); // Total Virtual Memory
				System.out.flush();

				ts = te;
				count = 0;
				b = 0;
				h = 0;
			}
		}
		// System.out.println();

		end = System.currentTimeMillis();
		double delta = ((double) end - (double) start) / 1000.;
		double hps = ((double) headers / 1000 / delta);
		double sph = 1000000000. / (headers / delta);

		long d = (end - start) / 1000;
		long seconds = (d % 60);
		long minutes = ((d / 60) % 60);
		long hours = ((d / 3600) % 24);

		System.out.printf("### %02d:%02d:%02d%n", hours, minutes, seconds);

		System.out.flush();

		queue.clear();
	}

	/**
	 * Load all packets from files.
	 * 
	 * @param files
	 *          the files
	 * @return the j pcap record buffer
	 */

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#runTest()
	 */
	@Override
	protected void runTest() throws Throwable {

		System.out.printf("============== %s ==============%n", getName());
		super.runTest();
	}

}
