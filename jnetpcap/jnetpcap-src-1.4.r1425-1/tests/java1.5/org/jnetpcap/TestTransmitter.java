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

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import junit.framework.TestCase;
import junit.textui.TestRunner;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class TestTransmitter
    extends
    TestCase {

	/** The Constant linux. */
	private final static String linux = "any";

	/** The Constant device. */
	private final static String device = linux;

	/** The Constant OK. */
	private static final int OK = 0;

	/** The Constant snaplen. */
	private static final int snaplen = 64 * 1024;

	/** The Constant promisc. */
	private static final int promisc = 1;

	/** The Constant oneSecond. */
	private static final int oneSecond = 1000;

	/**
	 * Will generate HTTP traffic to a website. Use start() to start in a test
	 * method, and always put stop() in tearDown. Safe to call stop even when
	 * never started.
	 */
	private static final HttpTrafficGenerator gen = new HttpTrafficGenerator();

	/** The tmp file. */
	private static File tmpFile;

	static {
		try {
			tmpFile = File.createTempFile("temp-", "-TestPcapJNI");
		} catch (IOException e) {
			tmpFile = null;
			System.err.println("Unable to initialize a temporary file");
		}

	}

	/**
	 * Command line launcher to run the jUnit tests cases in this test class.
	 * 
	 * @param args
	 *          -h for help
	 */
	public static void main(String[] args) {
		if (args.length == 1 && "-h".equals(args[0])) {
			System.out
			    .println("Usage: java -jar jnetpcap.jar [-h]\n"
			        + "  -h  This help message\n"
			        + "   (No other command line options are supported.)\n"
			        + "----------------------------------------------------------------\n\n"
			        + "The 'main' method invoked here, runs several dozen jUnit tests\n"
			        + "which test the functionality of this jNetPcap library.\n"
			        + "The tests are actual excersizes using native libpcap\n"
			        + "library linked with 'jnetpcap.dll' or 'libjnetpcap.so' on\n"
			        + "unix systems.\n\n"
			        + "If you are having trouble linking the native library and get\n"
			        + "'UnsatisfiedLinkError', which means java is not finding the\n"
			        + "library, here are a few pointers:\n\n"
			        + "Java's native library loader DOES NOT USE CLASSPATH variable\n"
			        + "to locate native libraries. Each operating system uses different\n"
			        + "algorithm to locate files, as described below. You can always\n"
			        + "force java to look for native library with Java VM command\n"
			        + "line option 'java -Djava.library.path=lib' where lib is\n"
			        + "a directory where 'jnetpcap.dll' or 'libjnetpcap.so' resides\n"
			        + "relative to the installation directory of jNetStream package.\n"
			        + "Or replace lib with the directory where you have installed the\n"
			        + "library.\n\n"
			        + "On Win32 systems:\n"
			        + "  Windows systems use /windows and /windows/system32 folder\n"
			        + "  to search for jnetpcap.dll. Also the 'PATH' variable, the same\n"
			        + "  one used to specify executable commands, is used as well.\n\n"
			        + "On Unix systems:\n"
			        + "  All unix systems use the standard 'LD_LIBRARY_PATH' variable.\n\n"
			        + "Of course as mentioned earlier, to override this behaviour use\n"
			        + "the '-Djava.library.path=' directory, to force java to look in\n"
			        + "that particular directory. Do not set the path which includes the\n"
			        + "name of the library itself, just the directory to search in.\n\n"
			        + "Final note, native librariers can not be loaded from jar files.\n"
			        + "You have to extract it to a physical directory if you want java to\n"
			        + "load it. This was done purposely by Sun for security reasons.");

			return;
		}

		TestRunner.main(new String[] { "org.jnetpcap.TestPcapJNI" });

	}

	/** The errbuf. */
	private StringBuilder errbuf = new StringBuilder();

	/** The do nothing handler. */
	@SuppressWarnings("deprecation")
	private final PcapHandler<?> doNothingHandler = new PcapHandler<Object>() {

		public void nextPacket(
		    Object userObject,
		    long seconds,
		    int useconds,
		    int caplen,
		    int len,
		    ByteBuffer buffer) {
			// Do nothing handler
		}
	};

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {

		errbuf = new StringBuilder();

		if (tmpFile.exists()) {
			assertTrue(tmpFile.delete());
		}

	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	public void tearDown() throws Exception {
	}

	/**
	 * This is a tricky test that must be disabled by default. We create a dummy
	 * packet all filled with 0xFF for 14 bytes which is the size of ethernet
	 * frame. This should produce a broadcast frame.
	 */
	public void testSendPacketUsingByteArray() {

		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.ERROR || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}
		PcapIf device = alldevs.get(1); // We know we have atleast 1 device

		Pcap pcap =
		    Pcap.openLive(device.getName(), snaplen, 1, 10 * oneSecond, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		byte[] a = new byte[14];
		Arrays.fill(a, (byte) 0xff);

		ByteBuffer b = ByteBuffer.wrap(a);

		if (pcap.sendPacket(b) != Pcap.OK) {
			fail(pcap.getErr());
		}

		pcap.close();

	}

	/**
	 * This is a tricky test that must be disabled by default. We create a dummy
	 * packet all filled with 0xFF for 14 bytes which is the size of ethernet
	 * frame. This should produce a broadcast frame.
	 */
	public void testInjectPacket() {

		Pcap pcap = Pcap.openLive("eth0", snaplen, 1, 10 * oneSecond, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		byte[] a = new byte[14];
		Arrays.fill(a, (byte) 0xff);

		ByteBuffer b = ByteBuffer.wrap(a);

		if (pcap.inject(b) < 0) {
			fail(pcap.getErr());
		}

		pcap.close();

	}

	/**
	 * Test send packet using j buffer.
	 * 
	 * @throws UnknownHostException
	 *           the unknown host exception
	 */
	public void testSendPacketUsingJBuffer() throws UnknownHostException {
		JPacket packet =
		    new JMemoryPacket(JProtocol.ETHERNET_ID,
		        "0016b6c13cb10021 5db0456c08004500 "
		            + "00340e8e40008006 9c54c0a80165d822 "
		            + "b5b1c1cf005020ce 4303000000008002 "
		            + "2000d94300000204 05b4010303020101 " + "0402");

		InetAddress dst = InetAddress.getByName("201.1.1.1");
		InetAddress src = InetAddress.getByName("192.168.1.1");

		Ip4 ip = packet.getHeader(new Ip4());
		Tcp tcp = packet.getHeader(new Tcp());

		ip.destination(dst.getAddress());
		ip.source(src.getAddress());

		ip.checksum(ip.calculateChecksum());
		tcp.checksum(tcp.calculateChecksum());
		packet.scan(Ethernet.ID);

		System.out.println(packet);
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.ERROR || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}
		PcapIf device = alldevs.get(0); // We know we have atleast 1 device
		/***************************************************************************
		 * Second we open a network interface
		 **************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_NON_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		Pcap pcap =
		    Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		System.out.println("Device ->" + device.getName());

		try {
			if (pcap.sendPacket(packet) != Pcap.OK) {
				System.err.println(pcap.getErr());
			}
		} finally {
			/*************************************************************************
			 * Lastly we close
			 ************************************************************************/
			pcap.close();
			
			
		}
	}

}
