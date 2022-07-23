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

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.header.BindNetworkFamily;
import org.jnetpcap.header.MyHeader;
import org.jnetpcap.packet.JBinding.DefaultJBinding;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Scanner;
import org.jnetpcap.packet.structure.AnnotatedBindMethod;
import org.jnetpcap.packet.structure.AnnotatedBinding;
import org.jnetpcap.packet.structure.AnnotatedHeaderLengthMethod;
import org.jnetpcap.packet.structure.HeaderDefinitionError;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestJRegistry extends TestCase {

	/**
	 * A test class that simplifies creation of test bindings by not having it
	 * abstract :)
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class TestBinding extends DefaultJBinding {

		/**
		 * Instantiates a new test binding.
		 * 
		 * @param myId
		 *            the my id
		 * @param targetId
		 *            the target id
		 * @param dependencyIds
		 *            the dependency ids
		 */
		public TestBinding(int myId, int targetId, int... dependencyIds) {
			super(myId, targetId, dependencyIds);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.jnetpcap.packet.JBinding#checkLength(org.jnetpcap.packet.JPacket,
		 * int)
		 */
		/**
		 * Scan for next header.
		 * 
		 * @param packet
		 *            the packet
		 * @param offset
		 *            the offset
		 * @return the int
		 */
		public int scanForNextHeader(JPacket packet, int offset) {
			throw new UnsupportedOperationException("Not implemented yet");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JBinding#getSourceId()
		 */
		public int getSourceId() {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Not implemented yet");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.jnetpcap.packet.JBinding#isBound(org.jnetpcap.packet.JPacket,
		 * int)
		 */
		public boolean isBound(JPacket packet, int offset) {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Not implemented yet");
		}

	};

	/** The errors. */
	private List<HeaderDefinitionError> errors = new ArrayList<HeaderDefinitionError>();

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {

		/*
		 * Now reset error list and clear all the caches from all the relavent
		 * classes for our tests. For our tests we want all the classes to
		 * always do their annotation inspection instead of doing it once and
		 * caching it.
		 */
		errors.clear();
		AnnotatedBinding.clearCache();
		AnnotatedBindMethod.clearCache();
		AnnotatedHeaderLengthMethod.clearCache();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		if (errors.isEmpty() == false) {
			System.out.println("Found errors:");

			for (HeaderDefinitionError e : errors) {
				System.out.println(e.getMessage());
			}

			fail("Found " + errors.size() + " header definition errors");
		}
	}

	/**
	 * Test core protocol registration by j protocol.
	 * 
	 * @throws UnregisteredHeaderException
	 *             the unregistered header exception
	 */
	public void testCoreProtocolRegistrationByJProtocol()
			throws UnregisteredHeaderException {

		for (JProtocol p : JProtocol.values()) {
			assertEquals(p.toString(), p.getId(), JRegistry.lookupId(p));
		}
	}

	/**
	 * Test core protocol registration by class.
	 * 
	 * @throws UnregisteredHeaderException
	 *             the unregistered header exception
	 */
	public void testCoreProtocolRegistrationByClass()
			throws UnregisteredHeaderException {

		System.out.println(JRegistry.toDebugString());

		for (JProtocol p : JProtocol.values()) {
			assertEquals(p.toString(), p.getId(),
					JRegistry.lookupId(p.getHeaderClass()));
		}
	}

	/**
	 * Test core protocol registration by name.
	 * 
	 * @throws UnregisteredHeaderException
	 *             the unregistered header exception
	 */
	public void testCoreProtocolRegistrationByName()
			throws UnregisteredHeaderException {

		assertEquals(JProtocol.ETHERNET.toString(), Ethernet.ID,
				JRegistry.lookupId(Ethernet.class));
		assertEquals(JProtocol.IP4.toString(), JProtocol.IP4_ID,
				JRegistry.lookupId(Ip4.class));
		assertEquals(JProtocol.IP6.toString(), Ip6.ID,
				JRegistry.lookupId(Ip6.class));
	}

	/**
	 * Test extract binding from j header.
	 */
	public void testExtractBindingFromJHeader() {
		AnnotatedBinding.inspectJHeaderClass(MyHeader.class, errors);
	}

	/**
	 * Test j header annotated binding with packet.
	 */
	public void testJHeaderAnnotatedBindingWithPacket() {
		JBinding[] bindings = AnnotatedBinding.inspectJHeaderClass(
				MyHeader.class, errors);
		JBinding bindEthernet = bindings[0];
		System.out.println(bindEthernet.toString());

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		assertTrue("ethernet binding", bindEthernet.isBound(packet, 0));
	}

	/**
	 * Test all class annotated binding with packet.
	 */
	public void testAllClassAnnotatedBindingWithPacket() {
		JBinding[] bindings = AnnotatedBinding.inspectClass(
				BindNetworkFamily.class, errors);

		assertTrue("no bindings found", bindings.length > 0);
		JBinding bindEthernet = bindings[0];

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		System.out.println(bindEthernet.toString());
		assertTrue(bindEthernet.toString(), bindEthernet.isBound(packet, 0));

	}

	/**
	 * The Class TestBindings.
	 */
	@SuppressWarnings("unused")
	private static class TestBindings {

		/**
		 * Bind ip4 to ethernet.
		 * 
		 * @param packet
		 *            the packet
		 * @param eth
		 *            the eth
		 * @return true, if successful
		 */
		@Bind(from = Ip4.class, to = Ethernet.class)
		public static boolean bindIp4ToEthernet(JPacket packet, Ethernet eth) {
			return eth.type() == 0x800;
		}

	};

	/**
	 * The Class TestHeader.
	 */
	@SuppressWarnings("unused")
	private static class TestHeader extends JHeader {

		/**
		 * Field1.
		 * 
		 * @return the int
		 */
		@Field(offset = 0, length = 8)
		public int field1() {
			return super.getUByte(0);
		}

		/**
		 * Field2.
		 * 
		 * @return the int
		 */
		@Field(offset = 8)
		public int field2() {
			return super.getUByte(0);
		}

		/**
		 * Field2 length.
		 * 
		 * @return the int
		 */
		@Dynamic(Field.Property.LENGTH)
		public int field2Length() {
			return field1() * 8;
		}
	}

	/**
	 * Test annonymous binding.
	 */
	public void testAnnonymousBinding() {

		new AbstractBinding<Ethernet>(Ip4.class, Ethernet.class) {

			@Override
			public boolean isBound(JPacket packet, Ethernet header) {
				return header.type() == 0x800;
			}

		};

		Object o = new Object() {

			@SuppressWarnings("unused")
			@Bind(from = Ip4.class, to = Ethernet.class)
			public boolean bindIp4ToEthernet(JPacket packet, Ethernet ethernet) {
				return ethernet.type() == 0x800;
			}
		};
		AnnotatedBinding.inspectObject(o, errors);
	}

	/**
	 * Test registry dump.
	 * 
	 * @throws RegistryHeaderErrors
	 *             the registry header errors
	 */
	public void AtestRegistryDump() throws RegistryHeaderErrors {
		JRegistry.register(MyHeader.class);

		JRegistry.lookupId(MyHeader.class);

		Object o = new Object() {

			@SuppressWarnings("unused")
			@Bind(from = Ip4.class, to = MyHeader.class)
			public boolean bindIp4ToMyHeader(JPacket packet, MyHeader my) {
				return my.type() == 0x800;
			}

			@SuppressWarnings("unused")
			@Scanner(Ip4.class)
			public void scanIp4(JScan scan) {

			}
		};

		JRegistry.addBindings(o);
		JRegistry.setScanners(o);
		System.out.println(JRegistry.toDebugString());

		JRegistry.clearScanners(o);
		System.out.println(JRegistry.toDebugString());
	}

}
