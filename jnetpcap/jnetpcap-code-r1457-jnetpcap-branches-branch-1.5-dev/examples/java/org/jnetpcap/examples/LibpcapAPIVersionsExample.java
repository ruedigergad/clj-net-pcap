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
package org.jnetpcap.examples;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.Pcap.Direction;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * This example demonstrates how to check for and use various API version
 * specific libpcap functions. 'pcap' library, from tcpdump.org team, is
 * evolving and typically adds new function calls to its public API every year.
 * This creates a problem for jnetpcap library integrators as some needed
 * functionality may or may not be present on various client systems. Operating
 * system package installers can typically check for pre-requisite package
 * requirements and make sure that minimum versions of 'pcap' library are
 * installed first before jnetpcap package can be installed. However most users
 * of jnetpcap prefer to use ZIP or TAR format, which does not provide
 * dependency checking mechanism and its up to the user or JVM to resolve and
 * report problems are runtime. Java is also platform independent and writing
 * the code once and run anywhere is a bit more tricky to accomplish when you
 * have such native library dependencies.
 * <p>
 * jNetPcap version 1.4 introduces a new "native library" management package
 * which facilitates additional checks and information about the state of the
 * loaded native libraries. It allows very specific checks, at runtime, for
 * native symbols without causing exceptions or errors. The library package is
 * exposed through a small set of methods in the Pcap class. These methods make
 * it convenient and easy to check if specific 'pcap' library functionality
 * exists at runtime on any platform, client and even with specific runtime
 * setup.
 * </p>
 * <p>
 * By now, we are all familiar with the static methods
 * <code>Pcap.openLive</code>, <code>Pcap.openOffline</code> and
 * <code>Pcap.close</code>. These calls have been part of public 'pcap' library
 * API since the beginning and a user can correctly assume that they are always
 * present. The only time these calls are not present is when the native 'pcap'
 * library, on which jnetpcap library is dependent on, failed to load, which can
 * happen for any number of reasons; libpcap library not installed, system
 * library loading path variable incorrectly set, permissions, etc. All 3 of
 * these calls rely on a 'pcap' library functions which are exported as part of
 * public API. These are <code>pcap_open_live</code>,
 * <code>pcap_open_offline</code> and <code>pcap_close</code>. jNetPcap native
 * library calls on these native functions and relies on them to be linked in by
 * the JVM when the application starts up.
 * </p>
 * <p>
 * However the 'pcap' library continues to evolve and has been steadily adding
 * new functions to its public API. The most recent new functions are actually
 * quiet numerous and are only available with libpcap version 1.0.0 or above and
 * any of its derivatives such as WinPcap 4.1.1 and above. Since these symbols
 * are available only in the newest 'pcap' libraries, many existing and
 * especially older systems, may not have the latest 'pcap' library installed.
 * Two such new functions added to 'pcap' library are <code>pcap_create</code>
 * and <code>pcap_activate</code>. These functions create an unactivated pcap
 * handle and then activate it. This defers the activation to a later time and
 * allows other parameters to be set on the handle. Its a bit more flexible way
 * of setting various options, parameters and properties on the pcap handle
 * before it becomes active. Alternative would be to keep on expanding the
 * single static 'pcap_open_live' function call or provide others like it that
 * take additional parameters. This is not scalable and splitting the 'create'
 * handle and 'activate' into separate steps allows any number of new
 * properties, through their own setter functions, to be added to the API.
 * </p>
 * <p>
 * So how can we check if <code>pcap_create</code> and
 * <code>pcap_activate</code> function calls are available to us, on any
 * particular client? Our example program could be running on a windows, linux,
 * solaris or freebsd and few others. The <code>Pcap</code> class, provides
 * boolean methods that allow us to check for specific API functionality and let
 * us make appropriate decisions at runtime, if we can rely on the new API or do
 * we have to fallback on the ever present old API.
 * </p>
 * <p>
 * First off, our jnetpcap version has to be 1.4 or above in order to support
 * this new API in the <code>Pcap</code> class. This is easy enough since
 * library integrators typically supply the correct jnetpcap version with their
 * application. The 'pcap' library installed on the system may or may not be at
 * the correct version however, as we may have no control over the installed
 * packages on that particular system. Especially in client production
 * environments, changing or upgrading libraries is a lengthy process. So as
 * long as we have the jnetpcap version 1.4 or above. Our example application
 * will at least run.
 * </p>
 * <p>
 * In our example we first check, using <code>Pcap.isPcap100Loaded</code>
 * method, if 'pcap' API level 1.0.0 is currently loaded and available to us. If
 * yes, we can assume that new 'pcap' library calls, <code>pcap_create</code>
 * and <code>pcap_activate</code>, are available to us and we can use them.
 * These calls are exported in java via the <code>Pcap.create</code> and
 * <code>Pcap.activate</code> methods. With out the an explicit check with
 * <code>Pcap.isPcap100Loaded</code> these methods may work on some platforms
 * and throw <code>UnsatisfiedLinkException</code> on others, unless we have
 * very strict control over pre-installed 'pcap' libraries, as described in the
 * above paragraphs. So if we make the check first and fallback on
 * <code>Pcap.openLive</code> method to open the 'pcap' handle, we can write
 * code that will work on any platform.
 * 
 * <pre>
 * Pcap pcap;
 * if (Pcap.isPcap100Loaded()) {
 * 	pcap = Pcap.create(deviceName, errbuf);
 * 	// Rest of the logic goes here
 * 	pcap.activate();
 * } else {
 * 	pcap = Pcap.openLive(deviceName, snaplen, timeout, flags, errbuf);
 * }
 * 
 * try {
 * 	// Our main application logic goes here
 * } finally {
 * 	pcap.close();
 * }
 * </pre>
 * 
 * </p>
 * <p>
 * Our example uses <code>Pcap.isPcap100Loaded</code> to check if the new 'pcap'
 * library API 1.0.0 is available. If it is, it uses <code>Pcap.create</code>
 * and <code>Pcap.activate</code> to open the 'pcap' handle to our live network
 * interface in 2 separate steps. It also sets the familiar 'snaplen', 'timeout'
 * and other familiar properties manually and explicitly. The real power of the
 * new API are the new functions which allow changing the size of the ring
 * buffer that 'pcap' uses to store packets. This is especially important call
 * on systems that are run on virtual machines as the default buffer size does
 * not seem to be large enough under most circumstances. So lets get started
 * with out example.
 * </p>
 * 
 * 
 * @author Sly Technologies, Inc.
 * @Since 1.4
 */
public class LibpcapAPIVersionsExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			String description =
					(device.getDescription() != null) ? device.getDescription()
							: "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
		}

		PcapIf device = alldevs.get(0); // We know we have atleast 1 device
		System.out
				.printf("\nChoosing '%s' on your behalf:\n",
						(device.getDescription() != null) ? device.getDescription()
								: device.getName());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis

		/*
		 * Display a little message so that we know which API we are using in this
		 * example
		 */
		System.out.printf("Is 'pcap' library API 1.0.0 or above loaded? %s%n",
				Pcap.isPcap100Loaded());

		/*
		 * Now lets open a 'pcap' handle to a live network interface and start
		 * capturing, no matter which API version is available to us.
		 */
		Pcap pcap;
		if (Pcap.isPcap100Loaded()) {
			pcap = Pcap.create(device.getName(), errbuf);
			if (pcap == null) {
				System.err.printf("Error while opening device for capture: "
						+ errbuf.toString());
				return;
			}

			/* Set our standard properties */
			pcap.setSnaplen(snaplen);
			pcap.setPromisc(flags);
			pcap.setTimeout(timeout);

			/* Here are some new ones */
			pcap.setDirection(Direction.INOUT); // We now have IN, OUT or INOUT
			pcap.setBufferSize(128 * 1024 * 1024); // Set ring-buffer to 128Mb

			pcap.activate(); // Make our handle active and start capturing

		} else {
			pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

			if (pcap == null) {
				System.err.printf("Error while opening device for capture: "
						+ errbuf.toString());
				return;
			}
		}

		/*
		 * The rest of the example is normal and we correctly handled different
		 * versions of 'pcap' library API available to us at runtime, on any
		 * platform.
		 */

		/***************************************************************************
		 * Third we create a packet handler which will receive packets from the
		 * libpcap loop.
		 **************************************************************************/
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {

				System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
						new Date(packet.getCaptureHeader().timestampInMillis()),
						packet.getCaptureHeader().caplen(), // Length actually captured
						packet.getCaptureHeader().wirelen(), // Original length
						user // User supplied object
						);
			}
		};

		try {
			/*************************************************************************
			 * Fourth we enter the loop and tell it to capture 10 packets. The loop
			 * method does a mapping of pcap.datalink() DLT value to JProtocol ID,
			 * which is needed by JScanner. The scanner scans the packet buffer and
			 * decodes the headers. The mapping is done automatically, although a
			 * variation on the loop method exists that allows the programmer to
			 * specify exactly which protocol ID to use as the data link type for this
			 * pcap interface.
			 ************************************************************************/
			pcap.loop(10, jpacketHandler, "jNetPcap rocks!");

			/*************************************************************************
			 * Last thing to do is close the pcap handle
			 ************************************************************************/
		} finally {
			pcap.close();
		}
	}
}
