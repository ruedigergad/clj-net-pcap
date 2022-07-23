/**
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
package com.slytechs.library;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.winpcap.WinPcap;

import com.slytechs.library.JNILibrary;
import com.slytechs.library.JNISymbol;
import com.slytechs.library.NativeLibrary;

/**
 * @author Sly Technologies, Inc.
 * 
 */
public class TestLibrary extends TestUtils {

	/**
	 * @throws Exception
	 * @see org.jnetpcap.packet.TestUtils#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		JNILibrary.register(Pcap.class);
		super.setUp();
	}
	
	public void testDlopen() {
		long address = NativeLibrary.dlopen("jnetpcap");
		assertTrue("address = 0x" + address, address != 0);
	}
	
	public void testDlsymbols() {
		JNILibrary lib = JNILibrary.loadLibrary("jnetpcap-pcap100");
		assertNotNull(lib);
		
		System.out.printf("testDlsymbols() - lib=%X/%s%n", lib.address, lib.name);
		lib.dlsymbol("Java_org_jnetpcap_Pcap_close");
		lib.dlsymbol("pcap_open_live");
		lib.dlsymbol("Java_org_jnetpcap_Pcap_create");
		
	}
	
	public void testPcapCanSetRfMon() {
		assertTrue(Pcap.isLoaded("canSetRfmon"));
	}

	public void _testPcapCanSetRfMond() throws SecurityException,
			NoSuchMethodException {
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();

		Pcap.findAllDevs(alldevs, errbuf);
		Pcap pcap = Pcap.create(alldevs.get(0).getName(), errbuf);

		if (Pcap.isLoaded("canSetRfmon")) {
			pcap.canSetRfmon();
		}

		pcap.close();

	}

	public void testPcapGet080Library() {

		JNILibrary.register(Pcap.class);
		System.out.println(JNILibrary.toStringAllLibraries());
		assertTrue(Pcap.isPcap080Loaded());
		JNILibrary lib = JNILibrary.loadLibrary(Pcap.LIBRARY);
		assertNotNull(lib);
		assertTrue(lib.isLoaded());

		System.out.println(lib);
	}

	public void testPcapGet100Library() {

		JNILibrary lib = JNILibrary.loadLibrary(Pcap.PCAP100_WRAPPER);
		assertNotNull(lib);
		assertTrue(lib.errors.toString(), lib.isLoaded());

		System.out.println(lib);
	}

	public void testPcapGetSymbols() throws SecurityException,
			NoSuchMethodException {

		JNILibrary.register(Pcap.class);
		assertTrue(Pcap.isPcap080Loaded());
		JNILibrary.loadLibrary(Pcap.LIBRARY);
		Method create =
				Pcap.class.getMethod("create", String.class, StringBuilder.class);
		JNISymbol symbol = JNILibrary.findSymbol(create);
		assertNotNull(JNISymbol.toJNIName(create), symbol);

		System.out.println(symbol.toString());
	}

	public void testPcapRegister() {

		assertTrue(String.valueOf(Pcap.getPcap080LoadError()),
				Pcap.isPcap080Loaded());
		JNILibrary lib = JNILibrary.loadLibrary(Pcap.LIBRARY);

		System.out.println(lib);

	}

	public void testWinPcap() {
		JNILibrary.register(WinPcap.class);
		JNILibrary.register(JBuffer.class);
		JNILibrary.register(NativeLibrary.class);

		JNILibrary.loadLibrary(Pcap.LIBRARY);

		System.out.println(JNILibrary.toStringClassSymbols(NativeLibrary.class,
				JMemory.class));

	}

}
