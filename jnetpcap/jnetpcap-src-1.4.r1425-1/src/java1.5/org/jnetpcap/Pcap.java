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
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.nio.JNumber;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.Library;
import com.slytechs.library.LibraryInitializer;
import com.slytechs.library.LibraryMember;

// TODO: Auto-generated Javadoc
/**
 * <P>
 * This class is the main class peered with native <code>pcap_t</code> structure
 * in libpcap and winpcap library implementations. It provides a direct mapping
 * of various library methods from Java.
 * </P>
 * <h2>Getting started</h2>
 * <p>
 * <code>Pcap</code> class provides several static methods which allow discovery
 * of networking interfaces and then subsequently open up either
 * <code>openLive</code>, <code>openDead</code> or <code>openOffline</code> pcap
 * capture sessions. In all 3 cases a <code>Pcap</code> object is returned. The
 * object is backed by a C <code>pcap_t</code> structure outside of java VM
 * address space. Any non-static operations on the <code>Pcap</code> object, are
 * translated using java JNI API into corresponding Libpcap C calls and the
 * appropriate <code>pcap_t</code> C structure is supplied to complete the call.
 * </p>
 * <p>
 * After acquiring a <code>Pcap</code> object from above mentioned static
 * methods, you must call on {@link #close} call to release any Libpcap
 * resources and the backing C structure. The <code>Pcap</code> object does
 * implicitly call the {@link #close} method from its {@link #finalize} method,
 * but that will only happen when the <code>Pcap</code> is garbage collected.
 * Its best practice to remember to always call on {@link #close} when
 * <code>Pcap</code> object and capture session is no longer needed.
 * </p>
 * <p>
 * If <code>Pcap</code> object is closed and any of its non-static methods are
 * called on, after the close, {@link IllegalStateException} will be thrown.
 * </p>
 * <h3>Getting a list of network interfaces from Pcap</h3> Lets get started with
 * little example on how to inquire about available interfaces, ask the user to
 * pick one of those interfaces for us, open it for capture,
 * compile(PcapBpfProgram, String, int, int) and install a capture filter and
 * then start processing some packets captured as a result. This is all loosely
 * based on examples you will find on tcpdump.org website but updated for
 * jNetPCAP. As with libpcap, we first want to find out and get network
 * interface names so we can tell jNetPCAP to open one or more for reading. So
 * first we inquire about the list of interfaces on the system:
 * 
 * <pre>
 * StringBuilder errbuf = new StringBuilder();
 * List&lt;PcapIf&gt; ifs = new ArrayList&lt;PcapIf&gt;(); // Will hold list of devices
 * int statusCode = Pcap.findAllDevs(ifs, errbuf);
 * if (statusCode != Pcap.OK) {
 * 	System.out.println(&quot;Error occurred: &quot; + errbuf.toString());
 * 	return;
 * }
 * // We have a list of PcapIf devices to work with now.
 * 
 * </pre>
 * 
 * <p>
 * <b>Note:</b> the return value from {@link #findAllDevs} is an integer result
 * code, just like in the C counter part. The <code>ifs</code> list is filled in
 * with all the network devices as found from the corresponding C structure
 * <code>pcap_if</code> linked list returned from the C function call
 * findAllDevs.
 * </p>
 * <p>
 * Now that we have a list of devices, we we print out the list of them and ask
 * the user to pick one to open for capture:
 * 
 * <pre>
 * for (int i = 0; i &lt; ifs.size(); i++) {
 * 	System.out.println(&quot;#&quot; + i + &quot;: &quot; + ifs.get(i).getName());
 * }
 * 
 * String l = System.in.readline().trim();
 * Integer i = Integer.valueOf(l);
 * 
 * PcapIf netInterface = ifs.get(i);
 * </pre>
 * 
 * <h3>Opening a network interface for live capture</h3>
 * Next we open up a live capture from the network interface using
 * {@link #openLive(String, int, int, int, StringBuilder)}:
 * 
 * <pre>
 * int snaplen = 2048; // Truncate packet at this size
 * 
 * int promiscous = Pcap.MODE_PROMISCUOUS;
 * 
 * int timeout = 60 * 1000; // In milliseconds
 * 
 * Pcap pcap = Pcap.openLive(netInterface.getName(), snaplen, promiscous, timeout,
 * 		errbuf);
 * </pre>
 * 
 * Last argument is a buffer that will hold an error string, if error occures.
 * On error <code>openLive</code> will return null.
 * <h3>Compiling and applying a filter to network interface</h3>
 * Once we have an open interface for capture we can apply a filter to reduce
 * amount of packets captured to something that is interesting to us:
 * 
 * <pre>
 * PcapBpfProgram filter = new PcapBpfProgram();
 * String expression = &quot;port 23&quot;
 * int optimize = 0; // 1 means true, 0 means false
 * int netmask = 0;
 * 
 * int r = pcap.compile(PcapBpfProgram, String, int, int)(filter, expression, optimize, netmask);
 * if (r != Pcap.OK) {
 *   System.out.println(&quot;Filter error: &quot; + pcap.getErr());
 * }
 * pcap.setFilter(filter);
 * </pre>
 * 
 * <p>
 * If filter expression contained a syntax error, the return code will be -1 and
 * exact error message can be retrieved using {@link #getErr} method.
 * </p>
 * <p>
 * <b>Note of caution:</b> the <code>PcapBpfProgram</code> at the top of the
 * previous code section, can not be accessed until successfully filled in with
 * values in the <code>pcap.compile(PcapBpfProgram, String, int, int)</code>
 * code. If you try and access any of its methods an
 * <code>IllegalStateException</code> will be thrown. Only after a successful
 * call to <code>compile(PcapBpfProgram, String, int, int)</code> does the
 * object become usable. The object is peered with C structure and until
 * properly initialized, can not be accessed from java.
 * </p>
 * <h3>Dispatcher to receive packets as they arrive</h3> And lastly lets do
 * something with the data.
 * 
 * <pre>
 * PcapHandler&lt;PrintStream&gt; handler = new PcapHandler&lt;PrintStream&gt;() {
 * 
 * 	public void newPacket(PrintStream out, int caplen, int len, int seconds,
 * 			int usecs, ByteBuffer buffer) {
 * 
 * 		out.println(&quot;Packet captured on: &quot;
 * 				+ new Date(seconds * 1000).toString());
 * 	}
 * };
 * 
 * int cnt = 10; // Capture packet count
 * PrintStream out = System.out; // Our custom object to send into the handler
 * 
 * pcap.loop(cnt, handler, out); // Each packet will be dispatched to the handler
 * 
 * pcap.close();
 * </pre>
 * 
 * <p>
 * This sets up PCAP to capture 10 packets and notify our handler of each packet
 * as each one is captured. Then after 10 packets the loop exits and we call
 * pcap.close() to free up all the resources and we can safely throw away our
 * pcap object. Also you may be curious why we pass System.out as userData to
 * the loop handler. This is simply to demonstrate the typical usage for this
 * kind of parameter. In our case we could easily pass a different PrintStream
 * bound to lets say a network socket and our handler would produce output to
 * it.
 * </p>
 * <p>
 * Alternative way of capturing packets from any of the open pcap sessions is to
 * use {@link #dispatch(int, PcapPacketHandler, Object)} method, which works
 * very similarly to {@link #loop(int, PcapPacketHandler, Object)}. You can also
 * use {@link #next(PcapHeader, JBuffer)} and
 * {@link #nextEx(PcapHeader, JBuffer)} methods which will deliver 1 packet at a
 * time.
 * </p>
 * <h3>No packet data copies!</h3>
 * <p>
 * The packet data is delivered in a <code>java.nio.ByteBuffer</code>. The data
 * is not copied into the buffer, but a direct byte buffer is allocated and
 * wrapped around the packet data as returned from libpcap. No in memory copies
 * are performed, so if the native operating system supports no-copy packet
 * captures, the packet are delivered to Java without copies. Only a single
 * ByteBuffer object allocation is incurred.
 * </p>
 * <h3>Omitted methods from standard libpcap API</h3> Certain deprecated methods
 * from libpcap API have been omitted such as <code>lookupDev</code>,
 * <code>lookupNet</code>. Also any methods that return <code>FILE *</code>
 * since that is not appropriate for java environment. <h3>Multithreading issues
 * </h3>
 * <p>
 * <code>Pcap</code> class does not provide any multithreading capabilities. As
 * a pure wrapper for native <em>libpcap</em> library, <code>Pcap</code> does
 * not provide any additional locking or multithreaded paradigms. The most
 * suggesting method is the {@link #breakloop()}, which can only be used from
 * another thread. This is the extent of <code>Pcap</code>'s multithreading
 * capabilities and threads have to be synchronized externally. Extreme care
 * must be taken, to ensure that no two methods are in use at the same time,
 * with the exception of <code>breakloop()</code>. For example, calling on
 * {@link #close()} while a loop is still in progress will cause
 * <em>libpcap</em> libpcap to crash or core-dump which will also crash the
 * entire Java VM.
 * </p>
 * <h3>Libpcap API Versions and Compatibility</h3> Starting with version 1.4,
 * jNetPcap provides support for various libpcap API layers. You can check at
 * runtime, which libpcap API is supported on the current platform or
 * environment and make appropriate decisions. See {@link #isPcap100Supported}
 * for more information.
 * 
 * 
 * @author Sly Technologies, Inc.
 */
@Library(preload = {PcapDumper.class, PcapIf.class, PcapBpfProgram.class,
		PcapDumper.class

}, natives = {Pcap.WINPCAP_LIBRARY, Pcap.PCAP_LIBRARY, "packet"

}, jni = {Pcap.LIBRARY, Pcap.PCAP100_WRAPPER

})
public class Pcap {

	/**
	 * Enum table which specifies in which direction should pcap capture packets
	 * on a capture device. This table corresponds to the following native pcap
	 * enum type:
	 * 
	 * <pre>
	 * typedef enum {
	 *   PCAP_D_INOUT = 0,
	 *   PCAP_D_IN,
	 *   PCAP_D_OUT
	 * } pcap_direction_t;
	 * 
	 * </pre>
	 * 
	 * @since 1.4
	 * 
	 * @author Sly Technologies, Inc.
	 */
	public enum Direction {

		/** Captures only incoming packets. */
		IN,

		/** (default) Captures both incoming and outgoing packets. */
		INOUT,

		/** Caputures only outgoing packets. */
		OUT,

	}

	/**
	 * Default JBufferSize used by loop and dispatch methods that utilize this
	 * type of buffer. Default value is {@value #DEFAULT_JPACKET_BUFFER_SIZE}.
	 */
	public static final int DEFAULT_JPACKET_BUFFER_SIZE = 1024 * 1024;

	/**
	 * Default capture promiscous mode to be used (default:.
	 * {@value #DEFAULT_PROMISC})
	 */
	public static final int DEFAULT_PROMISC = 1;

	/**
	 * Default capture SNAP len to be used (default: {@value #DEFAULT_SNAPLEN}).
	 */
	public static final int DEFAULT_SNAPLEN = 64 * 1024;

	/** Default capture timeout (default: {@value #DEFAULT_TIMEOUT}). */
	public static final int DEFAULT_TIMEOUT = 0;

	/**
	 * Value of packet count argument for <code>dispatch</code> method call
	 * which indicates that only as many packets should be returned as will fit
	 * in a single buffer , unless an error occured or <code>breakloop</code>
	 * call was used to interrupt the dispatcher. Note, that this constant is
	 * only appropriate value for <code>dispatch</code> method call. Loop method
	 * uses LOOP_INFINITE for something similar, but definately not identical to
	 * this option.
	 */
	public static final int DISPATCH_BUFFER_FULL = -1;

	/** generic error code. */
	public static final int ERROR = -1;

	/** the operation can't be performed on already activated captures. */
	public static final int ERROR_ACTIVATED = -4;

	/** loop terminated by pcap_breakloop. */
	public static final int ERROR_BREAK = -2;

	/** if the capture source is not up. */
	public static final int ERROR_IFACE_NOT_UP = -9;

	/**
	 * if the capture source specified when the handle was created doesn't
	 * exist.
	 */
	public static final int ERROR_NO_SUCH_DEVICE = -5;

	/** the capture needs to be activated. */
	public static final int ERROR_NOT_ACTIVATED = -3;

	/** operation supported only in monitor mode. */
	public static final int ERROR_NOT_RFMON = -7;

	/** if the process doesn't have permission to open the capture source. */
	public static final int ERROR_PERM_DENIED = -8;

	/**
	 * if monitor mode was specified but the capture source doesn't support
	 * monitor mode.
	 */
	public static final int ERROR_RFMON_NOTSUP = -6;

	/**
	 * Direction constant for use with {@link #setDirection(int) setDirection}
	 * which indicates the inbound direction. @since 1.4
	 */
	public static final int IN = 1;

	/**
	 * Direction constant for use with {@link #setDirection(int) setDirection}
	 * which indicates both in and out directions. @since 1.4
	 */
	public static final int INOUT = 0;

	/** Name of the native library that wraps around libpcap and extensions. */
	public static final String JNETPCAP_LIBRARY_NAME = "jnetpcap";

	/** The Constant LIBRARY. */
	public static final String LIBRARY = "jnetpcap";

	/** The LIBRAR y_ loa d_ status. */
	private static boolean LIBRARY_LOAD_STATUS;

	/**
	 * Value of packet count argument for <code>loop</code> method call which
	 * indicates that the loop should never exit, unless an error occured or
	 * <code>breakloop</code> call was used to interrupt the dispatcher. Note,
	 * that this constant is not appropriate value for <code>dispatch</code>
	 * method call, which has a different meaning.
	 * 
	 * @deprecated use {@link #LOOP_INFINITE} due to misspelled name
	 */
	@Deprecated
	public static final int LOOP_INFINATE = -1;

	/**
	 * Value of packet count argument for <code>loop</code> method call which
	 * indicates that the loop should never exit, unless an error occured or
	 * <code>breakloop</code> call was used to interrupt the dispatcher. Note,
	 * that this constant is not appropriate value for <code>dispatch</code>
	 * method call, which has a different meaning.
	 */
	public static final int LOOP_INFINITE = -1;

	/**
	 * Pcap status return code for <code>loop</code> and <code>dispatch</code>
	 * methods. This status code indicates that the the dispatcher was
	 * interrupted by a call to <code>breakloop</code> call.
	 * 
	 * @deprecated use {@link #ERROR_BREAK}
	 */
	@Deprecated
	public static final int LOOP_INTERRUPTED = -2;

	/**
	 * Flag which can be used with <code>setNonBlock</code> method to set the
	 * previously opened pcap descriptor into 'blocking' mode. The flag can also
	 * be the return code from <code>getNonBlock</code>. The flag has no affect
	 * on 'savefiles'.
	 */
	public static final int MODE_BLOCKING = 0;

	/**
	 * Flag which can be used with <code>setNonBlock</code> method to set the
	 * previously opened pcap descriptor into 'non-blocking' mode. The flag can
	 * also be the return code from <code>getNonBlock</code>. The flag has no
	 * affect on 'savefiles'.
	 */
	public static final int MODE_NON_BLOCKING = 1;

	/**
	 * Flag used with <code>openLive</code> to specify that the interface should
	 * not be put into promisuous mode, but only if poassible. Note, the even
	 * though the flag is specified, the interface could still be opened in
	 * promiscous mode for other reasons, such as a different process had
	 * already put the interface into promiscuous mode.
	 */
	public static final int MODE_NON_PROMISCUOUS = 0;

	/**
	 * Flag used with <code>openLive</code> to specify that the interface should
	 * be put into promisuous mode.
	 */
	public static final int MODE_PROMISCUOUS = 1;

	/**
	 * Exit code for <code>nextEx</code> method which indicates that pcap
	 * reached end of file while reading a 'savefile'.
	 */
	public static final int NEXT_EX_EOF = -2;

	/**
	 * Exit code for <code>nextEx</code> method which indicates failure of some
	 * kind. Use {@link #getErr()} to retrieve the error message.
	 */
	public static final int NEXT_EX_NOT_OK = -1;

	/**
	 * Exit code for <code>nextEx</code> method which indicates success.
	 */
	public static final int NEXT_EX_OK = 1;

	/**
	 * Exit code for <code>nextEx</code> method which indicates timeout has
	 * expired before a packet was captured. The packet header and packet buffer
	 * do no point to any valid data.
	 */
	public static final int NEXT_EX_TIMEDOUT = 0;

	/**
	 * Pcap status return code for most of the methods defined here. All methods
	 * that return an intenger as a status code, use this constants as meaning
	 * the call failed.
	 * 
	 * @deprecated use {@link #ERROR} or {@link #WARNING}
	 */
	@Deprecated
	public static final int NOT_OK = -1;

	/**
	 * Pcap status return code for most of the methods defined here. All methods
	 * that return an intenger as a status code, use this constants as meaning
	 * the call succeeded.
	 */
	public static final int OK = 0;

	/**
	 * Direction constant for use with {@link #setDirection(int) setDirection}
	 * which indicates the outbound direction. @since 1.4
	 */
	public static final int OUT = 2;

	/** The Constant PCAP_LIBRARY. */
	public static final String PCAP_LIBRARY = "pcap";

	/** The Constant PCAP100_LOAD_STATUS. */
	public static final boolean PCAP100_LOAD_STATUS;

	/** The Constant PCAP100_WRAPPER. */
	public static final String PCAP100_WRAPPER = "jnetpcap-pcap100";

	/** on success with any other warning. */
	public static final int WARNING = 1;

	/**
	 * on success on a device that doesn't support promiscuous mode if
	 * promiscuous mode was requested.
	 */
	public static final int WARNING_PROMISC_NOT_SUP = 2;

	/** The Constant WINPCAP_LIBRARY. */
	public static final String WINPCAP_LIBRARY = "wpcap";

	/**
	 * Static initializer
	 */
	static {

		JNILibrary.register(Pcap.class);

		LIBRARY_LOAD_STATUS = JNILibrary.loadLibrary(Pcap.LIBRARY).isLoaded();
		PCAP100_LOAD_STATUS = JNILibrary.loadLibrary(Pcap.PCAP100_WRAPPER)
				.isLoaded();

		// initIDs();
	}

	/**
	 * <p>
	 * Compile a packet filter without the need of opening an adapter. This
	 * function converts an high level filtering expression (see Filtering
	 * expression syntax) in a program that can be interpreted by the
	 * kernel-level filtering engine.
	 * </p>
	 * <p>
	 * 
	 * @param snaplen
	 *            generate code to truncate packets to this length upon a match
	 * @param dlt
	 *            the first header type within the packet, or data link type of
	 *            the interface
	 * @param program
	 *            initially empty, but after the method call will contain the
	 *            compile(PcapBpfProgram, String, int, int)d BPF program
	 * @param str
	 *            a string containing the textual expression to be
	 *            compile(PcapBpfProgram, String, int, int)d
	 * @param optimize
	 *            1 means to do optimizations, any other value means no
	 * @param netmask
	 *            netmask needed to determine the broadcast address
	 * @return a return of -1 indicates an error; the error text is unavailable;
	 *         lastly, the compile(PcapBpfProgram, String, int, int)d program is
	 *         stored and therefore returned in the formal parameter
	 *         <code>program</code>
	 *         {@link #compile(PcapBpfProgram, String, int, int)}_nopcap() is
	 *         similar to {@link #compile(PcapBpfProgram, String, int, int)}()
	 *         except that instead of passing a pcap structure, one passes the
	 *         snaplen and linktype explicitly. It is intended to be used for
	 *         compiling filters for direct BPF usage, without necessarily
	 *         having called pcap_open(). (
	 *         {@link #compile(PcapBpfProgram, String, int, int)}_nopcap() is a
	 *         wrapper around pcap_open_dead(),
	 *         {@link #compile(PcapBpfProgram, String, int, int)} (), and
	 *         pcap_close(); the latter three routines can be used directly in
	 *         order to get the error text for a compilation error.)
	 *         </p>
	 *         <p>
	 *         Look at the Filtering expression syntax section for details on
	 *         the str parameter.
	 *         </p>
	 * @deprecated use
	 *             {@link #compileNopcap(int, int, PcapBpfProgram, String, int, int)}
	 * @since 1.0
	 */
	@Deprecated
	public static int compile(int snaplen, int dlt, PcapBpfProgram program,
			String str, int optimize, int netmask) {
		return Pcap
				.compileNoPcap(snaplen, dlt, program, str, optimize, netmask);
	}

	/**
	 * <p>
	 * Compile a packet filter without the need of opening an adapter. This
	 * function converts an high level filtering expression (see Filtering
	 * expression syntax) in a program that can be interpreted by the
	 * kernel-level filtering engine.
	 * </p>
	 * <p>
	 * 
	 * @param snaplen
	 *            generate code to truncate packets to this length upon a match
	 * @param dlt
	 *            the first header type within the packet, or data link type of
	 *            the interface
	 * @param program
	 *            initially empty, but after the method call will contain the
	 *            compile(PcapBpfProgram, String, int, int)d BPF program
	 * @param str
	 *            a string containing the textual expression to be
	 *            compile(PcapBpfProgram, String, int, int)d
	 * @param optimize
	 *            1 means to do optimizations, any other value means no
	 * @param netmask
	 *            netmask needed to determine the broadcast address
	 * @return a return of -1 indicates an error; the error text is unavailable;
	 *         lastly, the compile(PcapBpfProgram, String, int, int)d program is
	 *         stored and therefore returned in the formal parameter
	 *         <code>program</code>
	 *         {@link #compile(PcapBpfProgram, String, int, int)}_nopcap() is
	 *         similar to {@link #compile(PcapBpfProgram, String, int, int)}()
	 *         except that instead of passing a pcap structure, one passes the
	 *         snaplen and linktype explicitly. It is intended to be used for
	 *         compiling filters for direct BPF usage, without necessarily
	 *         having called pcap_open(). (
	 *         {@link #compile(PcapBpfProgram, String, int, int)}_nopcap() is a
	 *         wrapper around pcap_open_dead(),
	 *         {@link #compile(PcapBpfProgram, String, int, int)} (), and
	 *         pcap_close(); the latter three routines can be used directly in
	 *         order to get the error text for a compilation error.)
	 *         </p>
	 *         <p>
	 *         Look at the Filtering expression syntax section for details on
	 *         the str parameter.
	 *         </p>
	 * @since 1.4
	 */
	@LibraryMember("pcap_compile_nopcap")
	public native static int compileNoPcap(int snaplen, int dlt,
			PcapBpfProgram program, String str, int optimize, int netmask);

	/**
	 * pcap_create() is used to create a packet capture handle to look at
	 * packets on the network. source is a string that specifies the network
	 * device to open; on Linux systems with 2.2 or later kernels, a source
	 * argument of "any" or NULL can be used to capture packets from all
	 * interfaces. The returned handle must be activated with pcap_activate()
	 * before pack' ets can be captured with it; options for the capture, such
	 * as promiscu' ous mode, can be set on the handle before activating it.
	 * 
	 * @param device
	 *            a string that specifies the network device to open; on Linux
	 *            systems with 2.2 or later kernels, a source argument of "any"
	 *            or NULL can be used to capture packets from all interfaces.
	 * @param errbuf
	 *            If NULL is returned, errbuf is filled in with an appropriate
	 *            error mes' sage
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_create")
	public native static Pcap create(String device, StringBuilder errbuf);

	/**
	 * Translates a data link type name, which is a DLT_ name with the DLT_
	 * removed, to the corresponding data link type value. The translation is
	 * case-insensitive. -1 is returned on failure.
	 * 
	 * @param name
	 *            data link type name
	 * @return data link type value or -1 on failure
	 */
	@LibraryMember("pcap_datalink_name_to_val")
	public native static int datalinkNameToVal(String name);

	/**
	 * Translates a data link type value to a short description of that data
	 * link type. NULL is returned on failure.
	 * 
	 * @param dlt
	 *            data link type value
	 * @return short description of that data link type, NULL is returned on
	 *         failure
	 */
	@LibraryMember("pcap_datalink_val_to_description")
	public native static String datalinkValToDescription(int dlt);

	/**
	 * Translates a data link type value to the corresponding data link type
	 * name. NULL is returned on failure.
	 * 
	 * @param dlt
	 *            data link type value
	 * @return data link type value to the corresponding data link type name,
	 *         NULL is returned on failure
	 */
	@LibraryMember("pcap_datalink_val_to_name")
	public native static String datalinkValToName(int dlt);

	/**
	 * pcap_findalldevs() constructs a list of network devices that can be
	 * opened with pcap_open_live(). (Note that there may be network devices
	 * that cannot be opened with pcap_open_live() by the process calling
	 * pcap_findalldevs(), because, for example, that process might not have
	 * sufficient privileges to open them for capturing; if so, those devices
	 * will not appear on the list.) alldevs is set to point to the first
	 * element of the list; each element of the list is of type pcap_if_t, and
	 * has the following members:
	 * <ul>
	 * <li>next if not NULL, a pointer to the next element in the list; NULL for
	 * the last element of the list
	 * <li>name a pointer to a string giving a name for the device to pass to
	 * pcap_open_live()
	 * <li>description if not NULL, a pointer to a string giving a
	 * human-readable description of the device
	 * <li>addresses a pointer to the first element of a list of addresses for
	 * the interface
	 * <li>flags interface flags: PCAP_IF_LOOPBACK set if the interface is a
	 * loopback interface
	 * </ul>
	 * Each element of the list of addresses is of type pcap_addr_t, and has the
	 * following members:
	 * <ul>
	 * <li>next if not NULL, a pointer to the next element in the list; NULL for
	 * the last element of the list
	 * <li>addr a pointer to a struct sockaddr containing an address
	 * <li>netmask if not NULL, a pointer to a struct sockaddr that contains the
	 * netmask corresponding to the address pointed to by addr
	 * <li>broadaddr if not NULL, a pointer to a struct sockaddr that contains
	 * the broadcast address corresponding to the address pointed to by addr;
	 * may be null if the interface doesn't support broadcasts
	 * <li>dstaddr if not NULL, a pointer to a struct sockaddr that contains the
	 * destination address corresponding to the address pointed to by addr; may
	 * be null if the interface isn't a point-to-point interface
	 * </ul>
	 * 
	 * @param alldevs
	 *            the list is filled in with <code>PcapIf</code> interface
	 *            objects; the list must not be immutable
	 * @param errbuf
	 *            error buffer containing error message as a string on failure
	 * @return -1 is returned on failure, in which case errbuf is filled in with
	 *         an appropriate error message; 0 is returned on success
	 * @since 1.2
	 */
	@LibraryMember("pcap_findalldevs")
	public native static int findAllDevs(List<PcapIf> alldevs,
			StringBuilder errbuf);

	/**
	 * This method does nothing. jNetPcap implementation frees up the device
	 * list immediately after its copied into Java objects in java space. The
	 * source structures are immediately released. pcap_freealldevs() is used to
	 * free a list allocated by pcap_findalldevs().
	 * 
	 * @param alldevs
	 *            is set to point to the first element of the list; each element
	 *            of the list is of type PcapIf
	 * @param errbuf
	 *            error buffer containing error message as a string on failure
	 * @deprecated use of byte[] errbuf is discouraged
	 * @see #freeAllDevs(List, StringBuilder)
	 */
	@Deprecated
	public static void freeAllDevs(List<PcapIf> alldevs, byte[] errbuf) {
		// Empty do nothing method, java PcapIf objects currently have no link
		// to C structures and do not need to be freed up. All the C structures
		// used to building PcapIf chains are already free.
		if (alldevs == null || errbuf == null) {
			throw new NullPointerException();
		}

		alldevs.clear();
	}

	/**
	 * This method does nothing. jNetPcap implementation frees up the device
	 * list immediately after its copied into Java objects in java space. The
	 * source structures are immediately released. pcap_freealldevs() is used to
	 * free a list allocated by pcap_findalldevs().
	 * 
	 * @param alldevs
	 *            is set to point to the first element of the list; each element
	 *            of the list is of type PcapIf
	 * @param errbuf
	 *            error buffer containing error message as a string on failure
	 * @since 1.2
	 */
	public static void freeAllDevs(List<PcapIf> alldevs, StringBuilder errbuf) {
		// Empty do nothing method, java PcapIf objects currently have no link
		// to C structures and do not need to be freed up. All the C structures
		// used to building PcapIf chains are already free.
		if (alldevs == null || errbuf == null) {
			throw new NullPointerException();
		}
		errbuf.setLength(0);
		alldevs.clear();
	}

	/**
	 * This frees up the code structures, but does not released the peered base
	 * bpf_program peer structure. Only the allocated storage to hold the code
	 * is freedup. The peered bpf_program structure is only freed when the
	 * program object is garbage collected.
	 * 
	 * @param program
	 *            program to free up the backend resources for
	 */
	@LibraryMember("pcap_freecode")
	public native static void freecode(PcapBpfProgram program);

	/**
	 * Gets the pcap080 load error.
	 * 
	 * @return the pcap080 load error
	 */
	public static Error getPcap080LoadError() {
		JNILibrary lib = JNILibrary.loadLibrary(Pcap.LIBRARY);
		return (lib.errors.isEmpty()) ? null : lib.errors.get(0);
	}

	/**
	 * Initializes JNI. Mainly prefetches all the JNI class, method and field
	 * IDs for everything that jnetpcap shared library needs inorder to interact
	 * with Java VM. This is done once and never has to be redone again. Once
	 * both the library are loaded and then JNI properly initializes itself,
	 * this method will have no effect.
	 * 
	 */
	@LibraryInitializer
	private native static void initIDs();

	/**
	 * Checks if the current platform has support for pcap_create,
	 * pcap_set_buffer_size, pcap_set_snaplen, pcap_set_timeout,
	 * pcap_setdirection, pcap_set_promisc, pcap_can_rfmon, pcap_set_rfmon,
	 * pcap_activate calls which are only availabled on platforms that support
	 * minimum libpcap version 1.0.0.
	 * 
	 * @return true if the set of the above functions is supported on the
	 *         platform otherwise false.
	 * @see #isPcap100Supported()
	 * @deprecated use {@link #isPcap100Supported} instead
	 */
	@Deprecated
	public native static boolean isCreateSupported();

	/**
	 * Checks if the current platform has support for pcap_inject call. The
	 * support is libpcap version and platform dependent.
	 * 
	 * @return true means {@link #inject(byte[])} is supported, otherwise not
	 * @see #inject(byte[])
	 */
	@LibraryMember("pcap_inject")
	public native static boolean isInjectSupported();

	/**
	 * Checks if is loaded.
	 * 
	 * @param methodName
	 *            the method name
	 * @param parameterTypes
	 *            the parameter types
	 * @return true, if is loaded
	 */
	public static boolean isLoaded(String methodName,
			Class<?>... parameterTypes) {
		return JNILibrary.findSymbol(Pcap.class, methodName, parameterTypes)
				.isLoaded();
	}

	/**
	 * Checks if pcap080 API is loaded.
	 * 
	 * @return true, if pcap080 API is loaded
	 */
	public static boolean isPcap080Loaded() {
		return LIBRARY_LOAD_STATUS;
	}

	/**
	 * Checks if the current version of libpcap installed on the system supports
	 * libpcap 1.0.0 API calls. The name Pcap100 stands for the name pcap 1.0.0,
	 * where 1.0.0 is compressed to 100.
	 * <p>
	 * This call is optional, normally the system packager ensures that the
	 * appropriate versions of the prerequisite libraries are installed. However
	 * it is never guarranteed how the user will setup their environmet. This
	 * call ensures that the programmer can handle even the extreme case, where
	 * installed libpcap version does not support libpcap 1.0.0 API calls.
	 * </p>
	 * <p>
	 * If this method evaluates to false, meaning that API calls are not
	 * available, all libpcap 1.0.0 related calls will throw
	 * 
	 * @return true if libpcap 1.0.0 API calls are available otherwise false
	 *         {@link UnsatisfiedLinkError}.
	 *         </p>
	 *         <p>
	 *         Example:
	 * 
	 *         <pre>
	 * StringBuilder errbuf = new StringBuilder();
	 * List&lt;PcapIf&gt; alldevs = new ArrayList&lt;PcapIf&gt;();
	 * int snaplen = 64 * 1024;
	 * int promisc = Pcap.MODE_PROMISCUOUS;
	 * int timeout = Pcap.DEFAULT_TIMEOUT;
	 * int bufsize = 128 * 1024 * 1024;
	 * int direction = Pcap.INOUT;
	 * 
	 * Pcap.findAllDevs(alldevs, errbuf);
	 * String device = alldevs.get(0).getName();
	 * 
	 * Pcap pcap;
	 * if (Pcap.isPcap100Supported()) {
	 * 	pcap = Pcap.create(device, errbuf);
	 * 
	 * 	pcap.setSnaplen(snaplen);
	 * 	pcap.setTimeout(timeout);
	 * 	pcap.setPromisc(promisc);
	 * 	pcap.setBufferSize(bufsize);
	 * 	pcap.setDirection(direction);
	 * 
	 * 	pcap.activate();
	 * 
	 * } else {
	 * 	pcap = Pcap.openLive(device, promisc, timeout, errbuf);
	 * }
	 * 
	 * pcap.close();
	 * </pre>
	 * 
	 *         </p>
	 * @since 1.4
	 * @see Pcap100
	 * @see #activate
	 * @see #create
	 * @see #canSetRfmon
	 * @see #setBufferSize
	 * @see #setDirection(int)
	 * @see #setDirection(org.jnetpcap.Pcap.Direction)
	 * @see #setPromisc
	 * @see #setRfmon
	 * @see #setSnaplen
	 * @see #setTimeout
	 */
	public static boolean isPcap100Loaded() {
		return PCAP100_LOAD_STATUS;
	}

	/**
	 * Checks if the current platform has support for pcap_sendpacket call. The
	 * support is libpcap version and platform dependent.
	 * 
	 * @return true means {@link #sendPacket(byte[])} is supported, otherwise
	 *         not
	 * @see #sendPacket(byte[])
	 */
	@LibraryMember("pcap_sendpacket")
	public native static boolean isSendPacketSupported();

	/**
	 * Returns a pointer to a string giving information about the version of the
	 * libpcap library being used; note that it contains more information than
	 * just a version number.
	 * 
	 * @return version of the libpcap library being used
	 */
	@LibraryMember("pcap_lib_version")
	public native static String libVersion();

	/**
	 * Returns a network device suitable for use with <code>openLive</code> and
	 * <code>lookupNet</code>.
	 * 
	 * @param errbuf
	 *            if there is an error, errbuf is filled with appropriate
	 *            message
	 * @return name of the device or null on error
	 */
	@LibraryMember("pcap_lookupdev")
	public native static String lookupDev(StringBuilder errbuf);

	/**
	 * Determines the network number and mask associated with the network
	 * device. Both netp and maskp are integer object references whos value is
	 * set from within the call. This is the way that pcap natively passes back
	 * these two values.
	 * <p>
	 * <b>Note:</b> this method is deprecated in pcap as it can not be used to
	 * pass back information about IP v6 addresses.
	 * </p>
	 * 
	 * @param device
	 *            device to do the lookup on
	 * @param netp
	 *            object which will contain the value of network address
	 * @param maskp
	 *            object which will contain the value of network netmask
	 * @param errbuf
	 *            any error messages if return value is -1
	 * @return 0 on success otherwise -1 on error
	 */
	@LibraryMember("pcap_lookupnet")
	public native static int lookupNet(String device, JNumber netp,
			JNumber maskp, StringBuilder errbuf);

	/**
	 * Determines the network number and mask associated with the network
	 * device. Both netp and maskp are integer object references whos value is
	 * set from within the call. This is the way that pcap natively passes back
	 * these two values.
	 * <p>
	 * <b>Note:</b> this method is deprecated in pcap as it can not be used to
	 * pass back information about IP v6 addresses.
	 * </p>
	 * 
	 * @param device
	 *            device to do the lookup on
	 * @param netp
	 *            object which will contain the value of network address
	 * @param maskp
	 *            object which will contain the value of network netmask
	 * @param errbuf
	 *            any error messages if return value is -1
	 * @return 0 on success otherwise -1 on error
	 * @deprecated use of PcapInteger has been deprecated
	 * @see #lookupNet(String, JNumber, JNumber, StringBuilder)
	 */
	@Deprecated
	@LibraryMember("pcap_lookupnet")
	public native static int lookupNet(String device, PcapInteger netp,
			PcapInteger maskp, StringBuilder errbuf);

	/**
	 * Create a pcap_t structure without starting a capture. pcap_open_dead() is
	 * used for creating a pcap_t structure to use when calling the other
	 * functions in libpcap. It is typically used when just using libpcap for
	 * compiling BPF code.
	 * 
	 * @param linktype
	 *            pcap DLT link type integer value
	 * @param snaplen
	 *            filters generated using the pcap structure will truncate
	 *            captured packets to this length
	 * @return Pcap structure that can only be used to generate filter code and
	 *         none of its other capture methods should be called or null if
	 *         error occured
	 */
	@LibraryMember("pcap_open_dead")
	public native static Pcap openDead(int linktype, int snaplen);

	/**
	 * <p>
	 * Open a live capture associated with the specified network interface
	 * device. pcap_open_live() is used to obtain a packet capture descriptor to
	 * look at packets on the network. device is a string that specifies the
	 * network device to open; on Linux systems with 2.2 or later kernels, a
	 * device argument of "any" or NULL can be used to capture packets from all
	 * interfaces. snaplen specifies the maximum number of bytes to capture. If
	 * this value is less than the size of a packet that is captured, only the
	 * first snaplen bytes of that packet will be captured and provided as
	 * packet data. A value of 65535 should be sufficient, on most if not all
	 * networks, to capture all the data available from the packet. promisc
	 * specifies if the interface is to be put into promiscuous mode. (Note that
	 * even if this parameter is false, the interface could well be in
	 * promiscuous mode for some other reason.)
	 * </p>
	 * <p>
	 * For now, this doesn't work on the "any" device; if an argument of "any"
	 * or NULL is supplied, the promisc flag is ignored. to_ms specifies the
	 * read timeout in milliseconds. The read timeout is used to arrange that
	 * the read not necessarily return immediately when a packet is seen, but
	 * that it wait for some amount of time to allow more packets to arrive and
	 * to read multiple packets from the OS kernel in one operation. Not all
	 * platforms support a read timeout; on platforms that don't, the read
	 * timeout is ignored. A zero value for to_ms, on platforms that support a
	 * read timeout, will cause a read to wait forever to allow enough packets
	 * to arrive, with no timeout. errbuf is used to return error or warning
	 * text. It will be set to error text when pcap_open_live() fails and
	 * returns NULL. errbuf may also be set to warning text when
	 * pcap_open_live() succeds; to detect this case the caller should store a
	 * zero-length string in errbuf before calling pcap_open_live() and display
	 * the warning to the user if errbuf is no longer a zero-length string.
	 * </p>
	 * <p>
	 * <b>Special note about <code>snaplen</code> argument.</b> The behaviour of
	 * this argument may be suprizing to some. The <code>argument</code> is only
	 * applied when there is a filter set using <code>setFilter</code> method
	 * after the <code>openLive</code> call. Otherwise snaplen, even non zero is
	 * ignored. This is the behavior of all BSD systems utilizing BPF and
	 * WinPcap. This may change in the future, but that is the current behavior.
	 * (For more detailed explanation and discussion please see jNetPcap website
	 * and its FAQs.)
	 * </p>
	 * 
	 * @param device
	 *            buffer containing a C, '\0' terminated string with the the
	 *            name of the device
	 * @param snaplen
	 *            amount of data to capture per packet; (see special note in doc
	 *            comments about when this argument is ignored even when
	 *            non-zero)
	 * @param promisc
	 *            1 means open in promiscious mode, a 0 means non-propmiscous
	 * @param timeout
	 *            timeout in ms
	 * @param errbuf
	 *            a buffer that will contain any error messages if the call to
	 *            open failed
	 * @return a raw structure the data of <code>pcap_t</code> C structure as
	 *         returned by native libpcap call to open
	 * @since 1.2
	 */
	@LibraryMember("pcap_open_live")
	public native static Pcap openLive(String device, int snaplen, int promisc,
			int timeout, StringBuilder errbuf);

	/**
	 * Open a savefile in the tcpdump/libpcap format to read packets.
	 * pcap_open_offline() is called to open a "savefile" for reading. fname
	 * specifies the name of the file to open. The file has the same format as
	 * those used by tcpdump(1) and tcpslice(1). The name "-" in a synonym for
	 * stdin. Alternatively, you may call pcap_fopen_offline() to read dumped
	 * data from an existing open stream fp. Note that on Windows, that stream
	 * should be opened in binary mode. errbuf is used to return error text and
	 * is only set when pcap_open_offline() or pcap_fopen_offline() fails and
	 * returns NULL.
	 * 
	 * @param fname
	 *            filename of the pcap file
	 * @param errbuf
	 *            any error messages in UTC8 encoding
	 * @return Pcap structure or null if error occured
	 * @since 1.2
	 */
	@LibraryMember("pcap_open_offline")
	public native static Pcap openOffline(String fname, StringBuilder errbuf);

	/**
	 * Physical address of the peering <code>pcap_t</code> C structure on native
	 * machine. <i>Libpcap</i> allocated this structure and deallocates it when
	 * {@link #close} is called. This is the reason that in {@link #finalize()}
	 * we call {@link #close} explicitely to let <i>Libpcap</i> free up the
	 * structure.
	 */
	private volatile long physical;

	private int id = -1;

	/**
	 * Pcap object can only be created by calling one of the static.
	 * 
	 * {@link #openLive} methods.
	 */
	public Pcap() {
		// Empty on purpose, the private field 'physical' is initialized
		// from JNI call. That is the only way it can be initialized.
	}

	/**
	 * Is used to activate a packet capture handle to look at packets on the
	 * network, with the options that were set on the handle being in effect.
	 * 
	 * @return returns 0 on success without warnings,
	 *         {@link #WARNING_PROMISC_NOT_SUP} on success on a device that
	 *         doesn't support promiscuous mode if promiscuous mode was
	 *         requested, {@link #WARNING} on success with any other warning,
	 *         {@link #ERROR_ACTIVATED} if the handle has already been
	 *         activated, {@link #ERROR_NO_SUCH_DEVICE} if the capture source
	 *         specified when the handle was created doesn't exist,
	 *         {@link #ERROR_PERM_DENIED} if the process doesn't have permission
	 *         to open the capture source, {@link #ERROR_RFMON_NOTSUP} if
	 *         monitor mode was specified but the capture source doesn't support
	 *         monitor mode, {@link #ERROR_IFACE_NOT_UP} if the capture source
	 *         is not up, and {@link #ERROR} if another error occurred.
	 *         <p>
	 *         If {@link #WARNING} or {@link #ERROR} is returned,
	 *         {@link #getErr()} gets the message describing the warning or
	 *         error. If {@link #WARNING_PROMISC_NOT_SUP},
	 *         {@link #ERROR_NO_SUCH_DEVICE}, or {@link #ERROR_PERM_DENIED} is
	 *         returned, {@link #getErr()} gets the message giving additional
	 *         details about the problem that might be useful for debugging the
	 *         problem if it's unexpected.
	 *         </p>
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_activate")
	public native int activate();

	/**
	 * <p>
	 * set a flag that will force pcap_dispatch() or pcap_loop() to return
	 * rather than looping. They will return the number of packets that have
	 * been processed so far, or -2 if no packets have been processed so far.
	 * This routine is safe to use inside a signal handler on UNIX or a console
	 * control handler on Windows, as it merely sets a flag that is checked
	 * within the loop. The flag is checked in loops reading packets from the OS
	 * - a signal by itself will not necessarily terminate those loops - as well
	 * as in loops processing a set of packets returned by the OS. Note that if
	 * you are catching signals on UNIX systems that support restarting system
	 * calls after a signal, and calling pcap_breakloop() in the signal handler,
	 * you must specify, when catching those signals, that system calls should
	 * NOT be restarted by that signal. Otherwise, if the signal interrupted a
	 * call reading packets in a live capture, when your signal handler returns
	 * after calling pcap_breakloop(), the call will be restarted, and the loop
	 * will not terminate until more packets arrive and the call completes.
	 * </p>
	 * <p>
	 * Note: pcap_next() will, on some platforms, loop reading packets from the
	 * OS; that loop will not necessarily be terminated by a signal, so
	 * pcap_breakloop() should be used to terminate packet processing even if
	 * pcap_next() is being used. pcap_breakloop() does not guarantee that no
	 * further packets will be processed by pcap_dispatch() or pcap_loop() after
	 * it is called; at most one more packet might be processed. If -2 is
	 * returned from pcap_dispatch() or pcap_loop(), the flag is cleared, so a
	 * subsequent call will resume reading packets. If a positive number is
	 * returned, the flag is not cleared, so a subsequent call will return -2
	 * and clear the flag.
	 * </p>
	 */
	@LibraryMember("pcap_breakloop")
	public native void breakloop();

	/**
	 * Check whether monitor mode can be set for a not-yet-activated capture
	 * handle. Checks whether monitor mode could be set on a capture handle when
	 * the handle is activated.
	 * 
	 * @return returns 0 if monitor mode could not be set, 1 if monitor mode
	 *         could be set, {@link #ERROR_NO_SUCH_DEVICE} if the device
	 *         specified when the handle was created doesn't exist,
	 *         {@link #ERROR_ACTIVATED} if called on a capture handle that has
	 *         been activated, or {@link #ERROR} if an error occurred. If
	 *         {@link #ERROR} is returned, {@link #getErr()} gets the error
	 *         text.
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_can_set_rfmon")
	public native int canSetRfmon();

	/**
	 * Checks if the current Pcap structure is active and open. It automatically
	 * throws an exception when its closed, but will not crash the VM. All
	 * dynamic non-native method in Pcap and any subclassed extensions should
	 * always make this call before attempting to do anything with pcap. The
	 * call makes sure that the pcap_t structure is still allocated and assigned
	 * to this object. If Pcap has been closed, no dynamic methods should be
	 * allowed to do anything. Native methods already perform this check. Static
	 * methods do not rely on pcap_t structure, since they are static, so they
	 * can not do this check.
	 * 
	 * @throws PcapClosedException
	 *             if pcap_t structure has been deallocated, another words if
	 *             Pcap.close has already been called.
	 */
	protected native void checkIsActive() throws PcapClosedException;

	/**
	 * pcap_close() closes the files associated with p and deallocates
	 * resources.
	 */
	@LibraryMember("pcap_close")
	public native void close();

	/**
	 * Compile a packet filter, converting a high level filtering expression in
	 * to a progra that can be interpreted by the kernel-level filtering engine.
	 * 
	 * @param program
	 *            initially empty, but after the method call will contain the
	 *            compile(PcapBpfProgram, String, int, int)d BPF program
	 * @param str
	 *            a string containing the textual expression to be
	 *            compile(PcapBpfProgram, String, int, int)d
	 * @param optimize
	 *            1 means to do optimizations, any other value means no
	 * @param netmask
	 *            netmask needed to determine the broadcast address
	 * @return A return of -1 indicates an error in which case {@link #getErr()}
	 *         may be used to display the error text.
	 */
	@LibraryMember("pcap_compile")
	public native int compile(PcapBpfProgram program, String str, int optimize,
			int netmask);

	/**
	 * Returns the link layer of an adapter.
	 * 
	 * @return PCAP link layer number
	 */
	@LibraryMember("pcap_datalink")
	public native int datalink();

	/**
	 * Performs a mapping of Pcap.datalink() to JRegistry ID. If doesn't exist
	 * defaults to ethernet.
	 * 
	 * @return JRegistry numerical ID for this datalink type.
	 */
	private int datalinkToId() {
		if (id == -1) {
			id = JRegistry.mapDLTToId(datalink());

			id = (id == JRegistry.NO_DLT_MAPPING) ? JProtocol.ETHERNET_ID : id;
		}

		return id;
	}

	/**
	 * <p>
	 * Collect a group of packets. pcap_dispatch() is used to collect and
	 * process packets. cnt specifies the maximum number of packets to process
	 * before returning. This is not a minimum number; when reading a live
	 * capture, only one bufferful of packets is read at a time, so fewer than
	 * cnt packets may be processed. A cnt of -1 processes all the packets
	 * received in one buffer when reading a live capture, or all the packets in
	 * the file when reading a ``savefile''. callback specifies a routine to be
	 * called with three arguments: a u_char pointer which is passed in from
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char
	 * pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
	 * to which is passed to the callback routine) bytes of data from the packet
	 * (which won't necessarily be the entire packet; to capture the entire
	 * packet, you will have to provide a value for snaplen in your call to
	 * pcap_open_live() that is sufficiently large to get all of the packet's
	 * data - a value of 65535 should be sufficient on most if not all
	 * networks).
	 * </p>
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read)
	 * or if no more packets are available in a ``savefile.'' A return of -1
	 * indicates an error in which case {@link #getErr()}() may be used to
	 * display the error text. A return of -2 indicates that the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at
	 * least one packet arrives. This means that the read timeout should NOT be
	 * used in, for example, an interactive application, to allow the packet
	 * capture loop to ``poll'' for user input periodically, as there's no
	 * guarantee that pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * 
	 * @param <T>
	 *            handler's user object type
	 * @param cnt
	 *            number of packets to read
	 * @param handler
	 *            called when packet arrives for each packet
	 * @param user
	 *            opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 * @since 1.2
	 */
	public <T> int dispatch(int cnt, ByteBufferHandler<T> handler, T user) {
		return dispatch(cnt, handler, user, new PcapHeader(Type.POINTER));
	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param cnt
	 *            the cnt
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param header
	 *            the header
	 * @return the int
	 */
	private native <T> int dispatch(int cnt, ByteBufferHandler<T> handler,
			T user, PcapHeader header);

	/**
	 * <p>
	 * Collect a group of packets. pcap_dispatch() is used to collect and
	 * process packets. cnt specifies the maximum number of packets to process
	 * before returning. This is not a minimum number; when reading a live
	 * capture, only one bufferful of packets is read at a time, so fewer than
	 * cnt packets may be processed. A cnt of -1 processes all the packets
	 * received in one buffer when reading a live capture, or all the packets in
	 * the file when reading a ``savefile''. callback specifies a routine to be
	 * called with three arguments: a u_char pointer which is passed in from
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char
	 * pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
	 * to which is passed to the callback routine) bytes of data from the packet
	 * (which won't necessarily be the entire packet; to capture the entire
	 * packet, you will have to provide a value for snaplen in your call to
	 * pcap_open_live() that is sufficiently large to get all of the packet's
	 * data - a value of 65535 should be sufficient on most if not all
	 * networks).
	 * </p>
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read)
	 * or if no more packets are available in a ``savefile.'' A return of -1
	 * indicates an error in which case {@link #getErr()}() may be used to
	 * display the error text. A return of -2 indicates that the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at
	 * least one packet arrives. This means that the read timeout should NOT be
	 * used in, for example, an interactive application, to allow the packet
	 * capture loop to ``poll'' for user input periodically, as there's no
	 * guarantee that pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param id
	 *            numerical protocol ID found in JProtocol.ID constant and in
	 *            JRegistery
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @return number of packet captured
	 */
	public <T> int dispatch(int cnt, int id, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, id, handler, user, packet, packet.getState(),
				packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Private native implemenation.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param cnt
	 *            the cnt
	 * @param id
	 *            the id
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param packet
	 *            the packet
	 * @param state
	 *            the state
	 * @param header
	 *            the header
	 * @param scanner
	 *            the scanner
	 * @return the int
	 */
	private native <T> int dispatch(int cnt, int id, JPacketHandler<T> handler,
			T user, JPacket packet, JPacket.State state, PcapHeader header,
			JScanner scanner);

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * <p>
	 * This method derrives the numerical protocol ID for the data link header
	 * automatically using <code>Pcap.datalink()</code> value returned.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param id
	 *            numerical protocol ID found in JProtocol.ID constant and in
	 *            JRegistery
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @return number of packet captured
	 */
	public <T> int dispatch(int cnt, int id, PcapPacketHandler<T> handler,
			T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, id, handler, user, packet, packet.getState(),
				packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Private native implementation.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param cnt
	 *            the cnt
	 * @param id
	 *            the id
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param packet
	 *            the packet
	 * @param state
	 *            the state
	 * @param header
	 *            the header
	 * @param scanner
	 *            the scanner
	 * @return the int
	 */
	private native <T> int dispatch(int cnt, int id,
			PcapPacketHandler<T> handler, T user, JPacket packet,
			JPacket.State state, PcapHeader header, JScanner scanner);

	/**
	 * <p>
	 * Collect a group of packets. pcap_dispatch() is used to collect and
	 * process packets. cnt specifies the maximum number of packets to process
	 * before returning. This is not a minimum number; when reading a live
	 * capture, only one bufferful of packets is read at a time, so fewer than
	 * cnt packets may be processed. A cnt of -1 processes all the packets
	 * received in one buffer when reading a live capture, or all the packets in
	 * the file when reading a ``savefile''. callback specifies a routine to be
	 * called with three arguments: a u_char pointer which is passed in from
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char
	 * pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
	 * to which is passed to the callback routine) bytes of data from the packet
	 * (which won't necessarily be the entire packet; to capture the entire
	 * packet, you will have to provide a value for snaplen in your call to
	 * pcap_open_live() that is sufficiently large to get all of the packet's
	 * data - a value of 65535 should be sufficient on most if not all
	 * networks).
	 * </p>
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read)
	 * or if no more packets are available in a ``savefile.'' A return of -1
	 * indicates an error in which case {@link #getErr()}() may be used to
	 * display the error text. A return of -2 indicates that the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at
	 * least one packet arrives. This means that the read timeout should NOT be
	 * used in, for example, an interactive application, to allow the packet
	 * capture loop to ``poll'' for user input periodically, as there's no
	 * guarantee that pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * 
	 * @param <T>
	 *            handler's user object type
	 * @param cnt
	 *            number of packets to read
	 * @param handler
	 *            called when packet arrives for each packet
	 * @param user
	 *            opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 * @since 1.2
	 */
	public <T> int dispatch(int cnt, JBufferHandler<T> handler, T user) {
		return dispatch(cnt, handler, user, new PcapHeader(Type.POINTER),
				new JBuffer(Type.POINTER));
	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param cnt
	 *            the cnt
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param header
	 *            the header
	 * @param buffer
	 *            the buffer
	 * @return the int
	 */
	private native <T> int dispatch(int cnt, JBufferHandler<T> handler, T user,
			PcapHeader header, JBuffer buffer);

	/**
	 * <p>
	 * Collect a group of packets. pcap_dispatch() is used to collect and
	 * process packets. cnt specifies the maximum number of packets to process
	 * before returning. This is not a minimum number; when reading a live
	 * capture, only one bufferful of packets is read at a time, so fewer than
	 * cnt packets may be processed. A cnt of -1 processes all the packets
	 * received in one buffer when reading a live capture, or all the packets in
	 * the file when reading a ``savefile''. callback specifies a routine to be
	 * called with three arguments: a u_char pointer which is passed in from
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char
	 * pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
	 * to which is passed to the callback routine) bytes of data from the packet
	 * (which won't necessarily be the entire packet; to capture the entire
	 * packet, you will have to provide a value for snaplen in your call to
	 * pcap_open_live() that is sufficiently large to get all of the packet's
	 * data - a value of 65535 should be sufficient on most if not all
	 * networks).
	 * </p>
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read)
	 * or if no more packets are available in a ``savefile.'' A return of -1
	 * indicates an error in which case {@link #getErr()}() may be used to
	 * display the error text. A return of -2 indicates that the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at
	 * least one packet arrives. This means that the read timeout should NOT be
	 * used in, for example, an interactive application, to allow the packet
	 * capture loop to ``poll'' for user input periodically, as there's no
	 * guarantee that pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * <p>
	 * This method derrives the numerical protocol ID for the data link header
	 * automatically using <code>Pcap.datalink()</code> value returned.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @return number of packet captured
	 */
	public <T> int dispatch(int cnt, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, datalinkToId(), handler, user, packet,
				packet.getState(), packet.getCaptureHeader(),
				JScanner.getThreadLocal());
	}

	/**
	 * <p>
	 * Collect a group of packets. pcap_dispatch() is used to collect and
	 * process packets. cnt specifies the maximum number of packets to process
	 * before returning. This is not a minimum number; when reading a live
	 * capture, only one bufferful of packets is read at a time, so fewer than
	 * cnt packets may be processed. A cnt of -1 processes all the packets
	 * received in one buffer when reading a live capture, or all the packets in
	 * the file when reading a ``savefile''. callback specifies a routine to be
	 * called with three arguments: a u_char pointer which is passed in from
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char
	 * pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
	 * to which is passed to the callback routine) bytes of data from the packet
	 * (which won't necessarily be the entire packet; to capture the entire
	 * packet, you will have to provide a value for snaplen in your call to
	 * pcap_open_live() that is sufficiently large to get all of the packet's
	 * data - a value of 65535 should be sufficient on most if not all
	 * networks).
	 * </p>
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read)
	 * or if no more packets are available in a ``savefile.'' A return of -1
	 * indicates an error in which case or {@link #getErr()}() may be used to
	 * display the error text. A return of -2 indicates that the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at
	 * least one packet arrives. This means that the read timeout should NOT be
	 * used in, for example, an interactive application, to allow the packet
	 * capture loop to ``poll'' for user input periodically, as there's no
	 * guarantee that pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * <p>
	 * This method derrives the numerical protocol ID for the data link header
	 * automatically using <code>Pcap.datalink()</code> value returned.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @param scanner
	 *            user supplied custom packet scanner
	 * @return number of packet captured
	 */
	public <T> int dispatch(int cnt, JPacketHandler<T> handler, T user,
			JScanner scanner) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, datalinkToId(), handler, user, packet,
				packet.getState(), packet.getCaptureHeader(), scanner);
	}

	/**
	 * A specialized dispatch method that utilizes a fast native dumper without
	 * entering java environment. A custom native pcap handler is provided that
	 * dumps all incoming packets to the dumper without any processing.
	 * 
	 * @param cnt
	 *            number of packets to read
	 * @param dumper
	 *            open pcap dumper to dump all packets to
	 * @return number of packets processed
	 */
	public native int dispatch(int cnt, PcapDumper dumper);

	/**
	 * Collect a group of packets. pcap_dispatch() is used to collect and
	 * process packets. cnt specifies the maximum number of packets to process
	 * before returning. This is not a minimum number; when reading a live
	 * capture, only one bufferful of packets is read at a time, so fewer than
	 * cnt packets may be processed. A cnt of -1 processes all the packets
	 * received in one buffer when reading a live capture, or all the packets in
	 * the file when reading a ``savefile''. callback specifies a routine to be
	 * called with three arguments: a u_char pointer which is passed in from
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char
	 * pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
	 * to which is passed to the callback routine) bytes of data from the packet
	 * (which won't necessarily be the entire packet; to capture the entire
	 * packet, you will have to provide a value for snaplen in your call to
	 * pcap_open_live() that is sufficiently large to get all of the packet's
	 * data - a value of 65535 should be sufficient on most if not all
	 * networks).
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read)
	 * or if no more packets are available in a ``savefile.'' A return of -1
	 * indicates an error in which case {@link #getErr()}() may be used to
	 * display the error text. A return of -2 indicates that the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at
	 * least one packet arrives. This means that the read timeout should NOT be
	 * used in, for example, an interactive application, to allow the packet
	 * capture loop to ``poll'' for user input periodically, as there's no
	 * guarantee that pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * 
	 * @param <T>
	 *            handler's user object type
	 * @param cnt
	 *            number of packets to read
	 * @param handler
	 *            called when packet arrives for each packet
	 * @param user
	 *            opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 * @deprecated user of PcapHandler has been replaced with ByteBufferHandler
	 * @see ByteBufferHandler
	 */
	@Deprecated
	public native <T> int dispatch(int cnt, PcapHandler<T> handler, T user);

	/**
	 * Collect a group of packets. pcap_dispatch() is used to collect and
	 * process packets. cnt specifies the maximum number of packets to process
	 * before returning. This is not a minimum number; when reading a live
	 * capture, only one bufferful of packets is read at a time, so fewer than
	 * cnt packets may be processed. A cnt of -1 processes all the packets
	 * received in one buffer when reading a live capture, or all the packets in
	 * the file when reading a ``savefile''. callback specifies a routine to be
	 * called with three arguments: a u_char pointer which is passed in from
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char
	 * pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
	 * to which is passed to the callback routine) bytes of data from the packet
	 * (which won't necessarily be the entire packet; to capture the entire
	 * packet, you will have to provide a value for snaplen in your call to
	 * pcap_open_live() that is sufficiently large to get all of the packet's
	 * data - a value of 65535 should be sufficient on most if not all
	 * networks).
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read)
	 * or if no more packets are available in a ``savefile.'' A return of -1
	 * indicates an error in which case {@link #getErr()}() may be used to
	 * display the error text. A return of -2 indicates that the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at
	 * least one packet arrives. This means that the read timeout should NOT be
	 * used in, for example, an interactive application, to allow the packet
	 * capture loop to ``poll'' for user input periodically, as there's no
	 * guarantee that pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * 
	 * @param <T>
	 *            handler's user object type
	 * @param cnt
	 *            number of packets to read
	 * @param handler
	 *            called when packet arrives for each packet
	 * @param user
	 *            opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 * @deprecated user of PcapHandler has been replaced with ByteBufferHandler
	 * @see ByteBufferHandler
	 */
	@Deprecated
	public <T> int dispatch(int cnt, PcapPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, datalinkToId(), handler, user, packet,
				packet.getState(), packet.getCaptureHeader(),
				JScanner.getThreadLocal());
	}

	/**
	 * Collect a group of packets. pcap_dispatch() is used to collect and
	 * process packets. cnt specifies the maximum number of packets to process
	 * before returning. This is not a minimum number; when reading a live
	 * capture, only one bufferful of packets is read at a time, so fewer than
	 * cnt packets may be processed. A cnt of -1 processes all the packets
	 * received in one buffer when reading a live capture, or all the packets in
	 * the file when reading a ``savefile''. callback specifies a routine to be
	 * called with three arguments: a u_char pointer which is passed in from
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char
	 * pointer to the first caplen (as given in the struct pcap_pkthdr a pointer
	 * to which is passed to the callback routine) bytes of data from the packet
	 * (which won't necessarily be the entire packet; to capture the entire
	 * packet, you will have to provide a value for snaplen in your call to
	 * pcap_open_live() that is sufficiently large to get all of the packet's
	 * data - a value of 65535 should be sufficient on most if not all
	 * networks).
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read)
	 * or if no more packets are available in a ``savefile.'' A return of -1
	 * indicates an error in which case {@link #getErr()}() may be used to
	 * display the error text. A return of -2 indicates that the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at
	 * least one packet arrives. This means that the read timeout should NOT be
	 * used in, for example, an interactive application, to allow the packet
	 * capture loop to ``poll'' for user input periodically, as there's no
	 * guarantee that pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * 
	 * @param <T>
	 *            handler's user object type
	 * @param cnt
	 *            number of packets to read
	 * @param handler
	 *            called when packet arrives for each packet
	 * @param user
	 *            opaque user object
	 * @param scanner
	 *            a custom user quick-scanner for parsing headers within the
	 *            packet
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 * @deprecated user of PcapHandler has been replaced with ByteBufferHandler
	 * @see ByteBufferHandler
	 */
	@Deprecated
	public <T> int dispatch(int cnt, PcapPacketHandler<T> handler, T user,
			JScanner scanner) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, datalinkToId(), handler, user, packet,
				packet.getState(), packet.getCaptureHeader(), scanner);
	}

	/**
	 * Open a file to write packets. The <code>dumpOpen</code> method is called
	 * to open a "savefile" for writing. The name '-' is a synonym for stdout.
	 * 
	 * @param fname
	 *            specifies the name of the file to open; currently the libpcap
	 *            option to open stdout by using "-" as a string, is not
	 *            supported by jNetPcap
	 * @return a dumper object or null on error; use <code>getErr</code> method
	 *         to retrieve the error message
	 */
	@LibraryMember("pcap_dump_open")
	public native PcapDumper dumpOpen(String fname);

	/**
	 * Cleanup before we're GCed. Will close connection to any open interface.
	 * Does nothing if connection already closed.
	 */
	@Override
	protected void finalize() {
		if (physical != 0) {
			close();
		}
	}

	/**
	 * return the error text pertaining to the last pcap library error.
	 * <p>
	 * Note: the pointer Return will no longer point to a valid error message
	 * string after the pcap_t passed to it is closed; you must use or copy the
	 * string before closing the pcap_t.
	 * </p>
	 * 
	 * @return the error text pertaining to the last pcap library error
	 */
	@LibraryMember("pcap_geterr")
	public native String getErr();

	/**
	 * pcap_getnonblock() returns the current ``non-blocking'' state of the
	 * capture descriptor; it always returns 0 on ``savefiles''. If there is an
	 * error, -1 is returned and errbuf is filled in with an appropriate error
	 * message.
	 * 
	 * @param errbuf
	 *            error buffer where error message will be stored on error
	 * @return if there is an error, -1 is returned and errbuf is filled in with
	 *         an appropriate error message
	 * @see #setNonBlock(int, StringBuilder)
	 * @since 1.2
	 */
	@LibraryMember("pcap_getnonblock")
	public native int getNonBlock(StringBuilder errbuf);

	/**
	 * This method allows to send a raw packet to the network. The MAC CRC
	 * doesn't need to be included, because it is transparently calculated and
	 * added by the network interface driver. The data will be taken from the
	 * supplied buffer where the start of the packet is buffer's current
	 * position() property and end its limit() properties.
	 * 
	 * @param buf
	 *            contains the data of the packet to send (including the various
	 *            protocol headers)
	 * @return 0 number of bytes written otherwise -1 on failure
	 */
	public int inject(final byte[] buf) {
		checkIsActive(); // Check if Pcap.close wasn't called

		final int length = buf.length;
		final ByteBuffer direct = ByteBuffer.allocateDirect(length);
		direct.put(buf);

		return injectPrivate(direct, 0, length);
	}

	/**
	 * This method allows to send a raw packet to the network. The MAC CRC
	 * doesn't need to be included, because it is transparently calculated and
	 * added by the network interface driver. The data will be taken from the
	 * supplied buffer where the start of the packet is buffer's current
	 * position() property and end its limit() properties.
	 * 
	 * @param buf
	 *            contains the data of the packet to send (including the various
	 *            protocol headers)
	 * @param offset
	 *            offset of the first index into the byte array
	 * @param length
	 *            amount of data to write from the offset
	 * @return 0 number of bytes written otherwise -1 on failure
	 */
	public int inject(final byte[] buf, int offset, int length) {
		checkIsActive(); // Check if Pcap.close wasn't called

		final ByteBuffer direct = ByteBuffer.allocateDirect(length);
		direct.put(buf, offset, length);

		return injectPrivate(direct, 0, length);
	}

	/**
	 * This method allows to send a raw packet to the network. The MAC CRC
	 * doesn't need to be included, because it is transparently calculated and
	 * added by the network interface driver. The data will be taken from the
	 * supplied buffer where the start of the packet is buffer's current
	 * position() property and end its limit() properties.
	 * 
	 * @param buf
	 *            contains the data of the packet to send (including the various
	 *            protocol headers); the buffer should be a direct buffer; array
	 *            based buffers will be copied into a direct buffer
	 * @return 0 number of bytes written otherwise -1 on failure
	 */
	public int inject(final ByteBuffer buf) {
		checkIsActive(); // Check if Pcap.close wasn't called

		if (buf.isDirect() == false) {
			final int length = buf.limit() - buf.position();
			final ByteBuffer direct = ByteBuffer.allocateDirect(length);
			direct.put(buf);

			return injectPrivate(direct, 0, length);
		} else {
			return injectPrivate(buf, buf.position(),
					buf.limit() - buf.position());
		}
	}

	/**
	 * Private method to perform work. The arguments are guarranteed to work
	 * with buf since we're using a delagate method.
	 * 
	 * @param buf
	 *            buffer contains raw data to send
	 * @param start
	 *            offset into the buffer
	 * @param len
	 *            number of bytes to send
	 * @return 0 number of bytes written otherwise -1 on failure
	 * @since 1.2
	 */
	@LibraryMember("pcap_inject")
	public native int inject(JBuffer buf, int start, int len);

	/**
	 * Private method to perform work. The arguments are guarranteed to work
	 * with buf since we're using a delagate method.
	 * 
	 * @param buf
	 *            buffer contains raw data to send
	 * @param start
	 *            offset into the buffer
	 * @param len
	 *            number of bytes to send
	 * @return 0 number of bytes written otherwise -1 on failure
	 */
	@LibraryMember("pcap_inject")
	private native int injectPrivate(ByteBuffer buf, int start, int len);

	/**
	 * returns true if the current savefile uses a different byte order than the
	 * current system.
	 * 
	 * @return 0 is false, non-zero is true
	 */
	@LibraryMember("pcap_is_swapped")
	public native int isSwapped();

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * 
	 * @param <T>
	 *            handler's user object type
	 * @param cnt
	 *            number of packets to read
	 * @param handler
	 *            called when packet arrives for each packet
	 * @param user
	 *            opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 * @since 1.2
	 */
	public <T> int loop(int cnt, ByteBufferHandler<T> handler, T user) {
		return loop(cnt, handler, user, new PcapHeader(Type.POINTER));
	}

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param cnt
	 *            the cnt
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param header
	 *            the header
	 * @return the int
	 */
	@LibraryMember("pcap_loop")
	private native <T> int loop(int cnt, ByteBufferHandler<T> handler, T user,
			PcapHeader header);

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * <p>
	 * This method derrives the numerical protocol ID for the data link header
	 * automatically using <code>Pcap.datalink()</code> value returned.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param id
	 *            numerical protocol ID found in JProtocol.ID constant and in
	 *            JRegistery
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	public <T> int loop(int cnt, final int id, final JPacketHandler<T> handler,
			T user) {
		return loop(cnt, new JBufferHandler<T>() {

			public void nextPacket(PcapHeader header, JBuffer buffer, T user) {

				final PcapPacket packet = new PcapPacket(header, buffer);
				packet.scan(id);

				handler.nextPacket(packet, user);
			}

		}, user);

	}

	/**
	 * Private native implementation.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param cnt
	 *            the cnt
	 * @param id
	 *            the id
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param packet
	 *            the packet
	 * @param state
	 *            the state
	 * @param header
	 *            the header
	 * @param scanner
	 *            the scanner
	 * @return the int
	 */
	@LibraryMember("pcap_loop")
	private native <T> int loop(int cnt, int id, JPacketHandler<T> handler,
			T user, JPacket packet, JPacket.State state, PcapHeader header,
			JScanner scanner);

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * <p>
	 * This method derrives the numerical protocol ID for the data link header
	 * automatically using <code>Pcap.datalink()</code> value returned.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param id
	 *            numerical protocol ID found in JProtocol.ID constant and in
	 *            JRegistery
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	public <T> int loop(int cnt, final int id,
			final PcapPacketHandler<T> handler, T user) {
		return loop(cnt, new JBufferHandler<T>() {

			public void nextPacket(PcapHeader header, JBuffer buffer, T user) {

				final PcapPacket packet = new PcapPacket(header, buffer);
				packet.scan(id);

				handler.nextPacket(packet, user);
			}

		}, user);
	}

	/**
	 * Private native implementation.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param cnt
	 *            the cnt
	 * @param id
	 *            the id
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param packet
	 *            the packet
	 * @param state
	 *            the state
	 * @param header
	 *            the header
	 * @param scanner
	 *            the scanner
	 * @return the int
	 */
	@LibraryMember("pcap_loop")
	private native <T> int loop(int cnt, int id, PcapPacketHandler<T> handler,
			T user, JPacket packet, JPacket.State state, PcapHeader header,
			JScanner scanner);

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * 
	 * @param <T>
	 *            handler's user object type
	 * @param cnt
	 *            number of packets to read
	 * @param handler
	 *            called when packet arrives for each packet
	 * @param user
	 *            opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 * @since 1.2
	 */
	public <T> int loop(int cnt, JBufferHandler<T> handler, T user) {
		return loop(cnt, handler, user, new PcapHeader(Type.POINTER),
				new JBuffer(Type.POINTER));
	}

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param cnt
	 *            the cnt
	 * @param handler
	 *            the handler
	 * @param user
	 *            the user
	 * @param header
	 *            the header
	 * @param buffer
	 *            the buffer
	 * @return the int
	 */
	@LibraryMember("pcap_loop")
	private native <T> int loop(int cnt, JBufferHandler<T> handler, T user,
			PcapHeader header, JBuffer buffer);

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	public <T> int loop(int cnt, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, datalinkToId(), handler, user, packet,
				packet.getState(), packet.getCaptureHeader(),
				JScanner.getThreadLocal());
	}

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @param scanner
	 *            user supplied custom packet scanner
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	public <T> int loop(int cnt, JPacketHandler<T> handler, T user,
			JScanner scanner) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, datalinkToId(), handler, user, packet,
				packet.getState(), packet.getCaptureHeader(), scanner);
	}

	/**
	 * A specialized loop method that utilizes a fast native dumper without
	 * entering java environment. A custom native pcap handler is provided that
	 * dumps all incoming packets to the dumper without any processing.
	 * 
	 * @param cnt
	 *            number of packets to read
	 * @param dumper
	 *            open pcap dumper to dump all packets to
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	@LibraryMember("pcap_loop")
	public native int loop(int cnt, PcapDumper dumper);

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * 
	 * @param <T>
	 *            handler's user object type
	 * @param cnt
	 *            number of packets to read
	 * @param handler
	 *            called when packet arrives for each packet
	 * @param user
	 *            opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 * @deprecated use of PcapHandler has been replaced with ByteBufferHandler
	 * @see ByteBufferHandler
	 */
	@Deprecated
	@LibraryMember("pcap_loop")
	public native <T> int loop(int cnt, PcapHandler<T> handler, T user);

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	public <T> int loop(int cnt, PcapPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, datalinkToId(), handler, user, packet,
				packet.getState(), packet.getCaptureHeader(),
				JScanner.getThreadLocal());
	}

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an
	 * error occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error;
	 * 0 is returned if cnt is exhausted; -2 is returned if the loop terminated
	 * due to a call to pcap_breakloop() before any packets were processed. If
	 * your application uses pcap_breakloop(), make sure that you explicitly
	 * check for -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet
	 * buffer as it is delivered by libpcap. The scanned information is recorded
	 * in native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer
	 * than a single iteration of the dispatcher, the delivered packets state
	 * must either be peered with a different packet (only copied by reference)
	 * or the entire contents and state must be copied to a new packet (a deep
	 * copy). The shallow copy by reference persists longer, but not
	 * indefinately. It persist as long as libpcap internal large capture buffer
	 * doesn't wrap around. The same goes for JScanner's internal scan buffer,
	 * it too persists until the state information exhausts the buffer and the
	 * buffer is wrapped around to the begining as well overriding any
	 * information in the scan buffer. If there are still any packets that
	 * reference that scan buffer information, once that information is
	 * overriden by the latest scan, the original scan information is gone
	 * forever and will guarrantee that any old packets still pointing at the
	 * scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * 
	 * @param <T>
	 *            user data type
	 * @param cnt
	 *            number of packets to process
	 * @param handler
	 *            user supplied packet handler
	 * @param user
	 *            a custom opaque user object
	 * @param scanner
	 *            user supplied custom packet scanner
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	public <T> int loop(int cnt, PcapPacketHandler<T> handler, T user,
			JScanner scanner) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, datalinkToId(), handler, user, packet,
				packet.getState(), packet.getCaptureHeader(), scanner);
	}

	/**
	 * Return the major version number of the pcap library used to write the
	 * savefile.
	 * 
	 * @return return the major version number of the pcap library used to write
	 *         the savefile
	 */
	@LibraryMember("pcap_major_version")
	public native int majorVersion();

	/**
	 * Return the minor version number of the pcap library used to write the
	 * savefile.
	 * 
	 * @return return the minor version number of the pcap library used to write
	 *         the savefile
	 */
	@LibraryMember("pcap_minor_version")
	public native int minorVersion();

	/**
	 * Return the next available packet. pcap_next() reads the next packet (by
	 * calling pcap_dispatch() with a cnt of 1) and returns a u_char pointer to
	 * the data in that packet. (The pcap_pkthdr struct for that packet is not
	 * supplied.) NULL is returned if an error occured, or if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read),
	 * or if no more packets are available in a ``savefile.'' Unfortunately,
	 * there is no way to determine whether an error occured or not.
	 * 
	 * @param pkt_header
	 *            a packet header that will be initialized to corresponding C
	 *            structure captured values
	 * @param buffer
	 *            a buffer that will be peered with returned buffer from libpcap
	 * @return buffer containing packet data or null if error occured
	 * @since 1.2
	 */
	@LibraryMember("pcap_next")
	public native JBuffer next(PcapHeader pkt_header, JBuffer buffer);

	/**
	 * Return the next available packet. pcap_next() reads the next packet (by
	 * calling pcap_dispatch() with a cnt of 1) and returns a u_char pointer to
	 * the data in that packet. (The pcap_pkthdr struct for that packet is not
	 * supplied.) NULL is returned if an error occured, or if no packets were
	 * read from a live capture (if, for example, they were discarded because
	 * they didn't pass the packet filter, or if, on platforms that support a
	 * read timeout that starts before any packets arrive, the timeout expires
	 * before any packets arrive, or if the file descriptor for the capture
	 * device is in non-blocking mode and no packets were available to be read),
	 * or if no more packets are available in a ``savefile.'' Unfortunately,
	 * there is no way to determine whether an error occured or not.
	 * 
	 * @param pkt_header
	 *            a packet header that will be initialized to corresponding C
	 *            structure captured values
	 * @return buffer containing packet data or null if error occured
	 * @deprecated use of PcapPktHdr has been replaced with PcapHeader
	 * @see PcapHeader
	 */
	@Deprecated
	@LibraryMember("pcap_next")
	public native ByteBuffer next(PcapPktHdr pkt_header);

	/**
	 * Read a packet from an interface or from an offline capture. This function
	 * is used to retrieve the next available packet, bypassing the callback
	 * method traditionally provided by libpcap. pcap_next_ex fills the
	 * pkt_header and pkt_data parameters (see pcap_handler()) with the pointers
	 * to the header and to the data of the next captured packet. </p>
	 * 
	 * @param pkt_header
	 *            a packet header that will be initialized to corresponding C
	 *            structure captured values
	 * @param buffer
	 *            buffer containing packet data or null if error occured
	 * @return the status code
	 *         <ul>
	 *         <li>1 if the packet has been read without problems
	 *         <li>0 if the timeout set with pcap_open_live() has elapsed. In
	 *         this case pkt_header and pkt_data don't point to a valid packet
	 *         <li>-1 if an error occurred
	 *         <li>-2 if EOF was reached reading from an offline capture
	 *         </ul>
	 * @since 1.2
	 */
	@LibraryMember("pcap_next_ex")
	public native int nextEx(PcapHeader pkt_header, JBuffer buffer);

	/**
	 * <p>
	 * Read a packet from an interface or from an offline capture. This function
	 * is used to retrieve the next available packet, bypassing the callback
	 * method traditionally provided by libpcap. The packet that is supplied as
	 * formal parameter, is used to peer, not copy, with the header and buffer
	 * of the next packet returned from libpcap. The supplied packet's
	 * PcapHeader is used to peer with the libpcap provided header and the
	 * packet object itself is used to peer with the libpcap provided packet
	 * buffer.
	 * </p>
	 * <p>
	 * The packet contents will point at libpcap buffer space which is not
	 * permanent. If packet contents are to be referenced on more permanent
	 * basis, it will be neccessary to copy the contents to a new packet. Here
	 * is a short example:
	 * 
	 * <pre>
	 * Pcap pcap = ...; // From somewhere
	 * PcapPacket packet = new PcapPacket(JMemory.POINTER);
	 * 
	 * while (nextEx(packet) == Pcap.NEXT_EX_OK) {
	 *   PcapPacket copy = new PcapPacket(packet); // Make the copy and new obj
	 * }
	 * </pre>
	 * 
	 * @param packet
	 *            packet that will be peered with the next libpcap returned
	 *            packet
	 * @return the status code
	 *         <ul>
	 *         <li>1 if the packet has been read without problems <li>0 if the
	 *         timeout set with pcap_open_live() has elapsed. In this case
	 *         pkt_header and pkt_data don't point to a valid packet <li>-1 if
	 *         an error occurred <li>-2 if EOF was reached reading from an
	 *         offline capture
	 *         </ul>
	 * @since 1.2
	 */
	public synchronized int nextEx(PcapPacket packet) {
		int r = nextEx(packet.getCaptureHeader(), packet);

		packet.scan(datalinkToId());

		return r;
	}

	/**
	 * Read a packet from an interface or from an offline capture. This function
	 * is used to retrieve the next available packet, bypassing the callback
	 * method traditionally provided by libpcap. pcap_next_ex fills the
	 * pkt_header and pkt_data parameters (see pcap_handler()) with the pointers
	 * to the header and to the data of the next captured packet. </p>
	 * 
	 * @param pkt_header
	 *            a packet header that will be initialized to corresponding C
	 *            structure captured values
	 * @param buffer
	 *            buffer containing packet data or null if error occured
	 * @return the status code
	 *         <ul>
	 *         <li>1 if the packet has been read without problems
	 *         <li>0 if the timeout set with pcap_open_live() has elapsed. In
	 *         this case pkt_header and pkt_data don't point to a valid packet
	 *         <li>-1 if an error occurred
	 *         <li>-2 if EOF was reached reading from an offline capture
	 *         </ul>
	 * @deprecated use PcapHeader and PcapPktBuffer has been deprecated
	 * @see PcapHeader
	 * @see JBuffer
	 */
	@Deprecated
	public native int nextEx(PcapPktHdr pkt_header, PcapPktBuffer buffer);

	/**
	 * This method allows to send a raw packet to the network. The MAC CRC
	 * doesn't need to be included, because it is transparently calculated and
	 * added by the network interface driver. The data will be taken from the
	 * supplied buffer where the start of the packet is buffer's current
	 * position() property and end its limit() properties.
	 * 
	 * @param buf
	 *            contains the data of the packet to send (including the various
	 *            protocol headers)
	 * @return 0 on success and -1 on failure
	 */
	public int sendPacket(final byte[] buf) {
		checkIsActive(); // Check if Pcap.close wasn't called

		final int length = buf.length;
		final ByteBuffer direct = ByteBuffer.allocateDirect(length);
		direct.put(buf);

		return sendPacketPrivate(direct, 0, length);
	}

	/**
	 * This method allows to send a raw packet to the network. The MAC CRC
	 * doesn't need to be included, because it is transparently calculated and
	 * added by the network interface driver. The data will be taken from the
	 * supplied buffer where the start of the packet is buffer's current
	 * position() property and end its limit() properties.
	 * 
	 * @param buf
	 *            contains the data of the packet to send (including the various
	 *            protocol headers)
	 * @param offset
	 *            offset of the first index into the byte array
	 * @param length
	 *            amount of data to write from the offset
	 * @return 0 on success and -1 on failure
	 */
	public int sendPacket(final byte[] buf, int offset, int length) {
		checkIsActive(); // Check if Pcap.close wasn't called

		final ByteBuffer direct = ByteBuffer.allocateDirect(length);
		direct.put(buf, offset, length);

		return sendPacketPrivate(direct, 0, length);
	}

	/**
	 * This method allows to send a raw packet to the network. The MAC CRC
	 * doesn't need to be included, because it is transparently calculated and
	 * added by the network interface driver. The data will be taken from the
	 * supplied buffer where the start of the packet is buffer's current
	 * position() property and end its limit() properties.
	 * 
	 * @param buf
	 *            contains the data of the packet to send (including the various
	 *            protocol headers); the buffer should be a direct buffer; array
	 *            based buffers will be copied into a direct buffer
	 * @return 0 on success and -1 on failure
	 */
	public int sendPacket(final ByteBuffer buf) {
		checkIsActive(); // Check if Pcap.close wasn't called

		if (buf.isDirect() == false) {
			final int length = buf.limit() - buf.position();
			final ByteBuffer direct = ByteBuffer.allocateDirect(length);
			direct.put(buf);

			return sendPacketPrivate(direct, 0, length);
		} else {
			return sendPacketPrivate(buf, buf.position(),
					buf.limit() - buf.position());
		}
	}

	/**
	 * This method allows to send a raw packet to the network. The MAC CRC
	 * doesn't need to be included, because it is transparently calculated and
	 * added by the network interface driver. The data will be taken from the
	 * supplied buffer where the start of the packet is buffer's current
	 * position() property and end its limit() properties.
	 * 
	 * @param buf
	 *            contains the data of the packet to send (including the various
	 *            protocol headers); the buffer should be a direct buffer; array
	 *            based buffers will be copied into a direct buffer
	 * @return 0 on success and -1 on failure
	 * @since 1.2
	 */
	@LibraryMember("pcap_sendpacket")
	public native int sendPacket(final JBuffer buf);

	/**
	 * Private method to perform work. The arguments are guarranteed to work
	 * with buf since we're using a delagate method.
	 * 
	 * @param buf
	 *            the buf
	 * @param start
	 *            the start
	 * @param len
	 *            the len
	 * @return the int
	 */
	private native int sendPacketPrivate(ByteBuffer buf, int start, int len);

	/**
	 * sets the buffer size that will be used on a capture handle when the
	 * handle is activated to buffer_size, which is in units of bytes.
	 * 
	 * @param size
	 *            size that will be used on a capture handle
	 * @return 0 on success or {@link #ERROR_ACTIVATED} if called on a capture
	 *         handle that has been activated.
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_set_buffer_size")
	public native int setBufferSize(long size);

	/**
	 * Set the current data link type of the pcap descriptor to the type
	 * specified by dlt.
	 * 
	 * @param dlt
	 *            new dlt
	 * @return -1 is returned on failure
	 */
	@LibraryMember("pcap_set_datalink")
	public native int setDatalink(int dlt);

	/**
	 * Set the direction for which packets will be captured. The method
	 * <code>setDirection()</code> is used to specify a direction that packets
	 * will be captured. dir is one of the constants {@link Direction#IN},
	 * 
	 * @param dir
	 *            direction that packets will be captured.
	 * @return returns 0 on success and {@link #ERROR} on failure. If
	 *         {@link Direction#OUT} or {@link Direction#INOUT}.
	 *         {@link Direction#IN} will only capture packets received by the
	 *         device, {@link Direction#OUT} will only capture packets sent by
	 *         the device and {@link Direction#INOUT} will capture packets
	 *         received by or sent by the device. {@link Direction#INOUT} is the
	 *         default setting if this function is not called.
	 *         <p>
	 *         pcap_setdirection() isn't necessarily fully supported on all
	 *         platforms; some platforms might return an error for all values,
	 *         and some other platforms might not support {@link Direction#OUT}.
	 *         </p>
	 *         <p>
	 *         This operation is not supported if a "savefile" is being read.
	 *         </p>
	 *         {@link #ERROR} is returned, {@link #getErr()} gets the error
	 *         text.
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * @author Sly Technologies, Inc.
	 */
	public int setDirection(Direction dir) {
		return setDirection(dir.ordinal());
	}

	/**
	 * Set the direction for which packets will be captured. The method
	 * <code>setDirection()</code> is used to specify a direction that packets
	 * will be captured. dir is one of the constants {@link Direction#IN},
	 * 
	 * @param dir
	 *            direction that packets will be captured.
	 * @return returns 0 on success and {@link #ERROR} on failure. If
	 *         {@link Direction#OUT} or {@link Direction#INOUT}.
	 *         {@link Direction#IN} will only capture packets received by the
	 *         device, {@link Direction#OUT} will only capture packets sent by
	 *         the device and {@link Direction#INOUT} will capture packets
	 *         received by or sent by the device. {@link Direction#INOUT} is the
	 *         default setting if this function is not called.
	 *         <p>
	 *         pcap_setdirection() isn't necessarily fully supported on all
	 *         platforms; some platforms might return an error for all values,
	 *         and some other platforms might not support {@link Direction#OUT}.
	 *         </p>
	 *         <p>
	 *         This operation is not supported if a "savefile" is being read.
	 *         </p>
	 *         <p>
	 *         This method is private since native method uses specific
	 *         pcap_direction_t enum structure to make the call and java int
	 *         doesn't provide the proper typesafety. This is why we use a
	 *         public method first requiring a java enum type, and convert that
	 *         to appropriate native integer value.
	 *         </p>
	 *         {@link #ERROR} is returned, {@link #getErr()} gets the error
	 *         text.
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_setdirection")
	public native int setDirection(int dir);

	/**
	 * Associate a filter to a capture. pcap_setfilter() is used to specify a
	 * filter program. fp is a pointer to a bpf_program struct, usually the
	 * result of a call to {@link #compile(PcapBpfProgram, String, int, int)}.
	 * -1 is returned on failure, in which case {@link #getErr()}() may be used
	 * to display the error text; 0 is returned on success.
	 * 
	 * @param program
	 *            the program
	 * @return -1 is returned on failure, in which case {@link #getErr()}() may
	 *         be used to display the error text; 0 is returned on success
	 */
	@LibraryMember("pcap_setfilter")
	public native int setFilter(PcapBpfProgram program);

	/**
	 * pcap_setnonblock() puts a capture descriptor, opened with
	 * pcap_open_live(), into ``non-blocking'' mode, or takes it out of
	 * ``non-blocking'' mode, depending on whether the nonblock argument is
	 * non-zero or zero. It has no effect on ``savefiles''. If there is an
	 * error, -1 is returned and errbuf is filled in with an appropriate error
	 * message; otherwise, 0 is returned. In ``non-blocking'' mode, an attempt
	 * to read from the capture descriptor with pcap_dispatch() will, if no
	 * packets are currently available to be read, return 0 immediately rather
	 * than blocking waiting for packets to arrive. pcap_loop() and pcap_next()
	 * will not work in ``non-blocking'' mode.
	 * 
	 * @param nonBlock
	 *            a non negative value means to set in non blocking mode
	 * @param errbuf
	 *            error buffer where error message will be stored on error
	 * @return if there is an error, -1 is returned and errbuf is filled in with
	 *         an appropriate error message
	 * @see #getNonBlock(StringBuilder)
	 * @since 1.2
	 */
	@LibraryMember("pcap_setnonblock")
	public native int setNonBlock(int nonBlock, StringBuilder errbuf);

	/**
	 * Set promiscuous mode for a not-yet-activated capture handle. Sets whether
	 * promiscuous mode should be set on a capture handle when the handle is
	 * activated. If promisc is non-zero, promiscuous mode will be set,
	 * otherwise it will not be set.
	 * 
	 * @param promisc
	 *            if promisc is non-zero, promiscuous mode will be set,
	 *            otherwise it will not be set
	 * @return returns 0 on success or {@link #ERROR_ACTIVATED} if called on a
	 *         capture handle that has been activated
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_set_promisc")
	public native int setPromisc(int promisc);

	/**
	 * Set monitor mode for a not-yet-activated capture handle.
	 * 
	 * @param rfmon
	 *            sets whether monitor mode should be set on a capture handle
	 *            when the handle is activated. If rfmon is non-zero, monitor
	 *            mode will be set, otherwise it will not be set.
	 * @return returns 0 on success or {@link #ERROR_ACTIVATED} if called on a
	 *         capture handle that has been activated
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_set_rfmon")
	public native int setRfmon(int rfmon);

	/**
	 * Set the snapshot length for a not-yet-activated capture handle. Sets the
	 * snapshot length to be used on a capture handle when the handle is
	 * activated to snaplen.
	 * 
	 * @param snaplen
	 *            snapshot length
	 * @return returns 0 on success or {@link #ERROR_ACTIVATED} if called on a
	 *         capture handle that has been activated
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_set_snaplen")
	public native int setSnaplen(int snaplen);

	/**
	 * Set the read timeout for a not-yet-activated capture handle. Sets the
	 * read timeout that will be used on a capture handle when the handle is
	 * activated to timeout, which is in units of milliseconds.
	 * 
	 * @param timeout
	 *            timeout value in milli seconds
	 * @return returns 0 on success or {@link #ERROR_ACTIVATED} if called on a
	 *         capture handle that has been activated
	 * @since 1.4
	 * @see #isPcap100Supported()
	 * 
	 * @author Sly Technologies, Inc.
	 */
	@LibraryMember("pcap_set_timeout")
	public native int setTimeout(int timeout);

	/**
	 * Return the dimension of the packet portion (in bytes) that is delivered
	 * to the application. pcap_snapshot() returns the snapshot length specified
	 * when pcap_open_live was called.
	 * 
	 * @return returns the snapshot length specified when
	 *         {@link #setSnaplen(int)} or
	 *         {@link #openLive(String, int, int, int, StringBuilder)} was
	 *         called, for a live capture, or the snapshot length from the
	 *         capture file, for a "savefile".
	 * @see #openLive(String, int, int, int, StringBuilder)
	 */
	@LibraryMember("pcap_snapshot")
	public native int snapshot();

	/**
	 * Returns statistics on the current capture. The method fills in the
	 * PcapStat structure. The values represent packet statistics from the start
	 * of the run to the time of the call.
	 * 
	 * @param stats
	 *            PcapStat object to fill in
	 * @return -1 if underlying packet capture doesn't support packet statistics
	 *         or if there is an error; use <code>getErr</code> to retrieve the
	 *         error message
	 */
	@LibraryMember("pcap_stats")
	public native int stats(PcapStat stats);

	/**
	 * Prints libVersion that Pcap is based on.
	 * 
	 * @return libpcap version in use by this pcap object
	 */
	@Override
	public String toString() {
		checkIsActive(); // Check if Pcap.close wasn't called

		return libVersion();
	}
}
