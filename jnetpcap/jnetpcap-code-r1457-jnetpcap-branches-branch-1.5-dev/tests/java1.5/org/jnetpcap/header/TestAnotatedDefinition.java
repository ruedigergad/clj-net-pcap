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
package org.jnetpcap.header;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.JFormatter.Detail;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.structure.AnnotatedBindMethod;
import org.jnetpcap.packet.structure.AnnotatedBinding;
import org.jnetpcap.packet.structure.AnnotatedField;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.AnnotatedHeaderLengthMethod;
import org.jnetpcap.packet.structure.AnnotatedJField;
import org.jnetpcap.packet.structure.HeaderDefinitionError;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestAnotatedDefinition extends TestCase {

	/** The errors. */
	private final List<HeaderDefinitionError> errors =
			new ArrayList<HeaderDefinitionError>();

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {

		/*
		 * Now reset error list and clear all the caches from all the relavent
		 * classes for our tests. For our tests we want all the classes to always do
		 * their annotation inspection instead of doing it once and caching it.
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
	@Override
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
	 * _test1.
	 */
	public void _test1() {

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		MyHeader my = new MyHeader();

		if (packet.hasHeader(my) && my.version() == 4) {
			System.out.printf("found it id=%d\n", my.getId());

			System.out.println(packet.toString());
		} else {
			System.out.printf("not found id=%d\n", my.getId());
		}
	}

	/**
	 * The Class TestHeader.
	 */
	@Header
	public static class TestHeader extends JHeader {

		/**
		 * Header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the int
		 */
		@HeaderLength
		public static int headerLength(JBuffer buffer, int offset) {
			return Ethernet.LENGTH;
		}

		/**
		 * Field a.
		 * 
		 * @return the int
		 */
		@Field(offset = 0, length = 16)
		public int fieldA() {
			return getUShort(12);
		}

		/**
		 * Field b.
		 * 
		 * @return the int
		 */
		@Field(offset = 0, length = 16)
		public int fieldB() {
			return getUShort(12);
		}

		/**
		 * Checks for field b_ sub1.
		 * 
		 * @return true, if successful
		 */
		@Dynamic(field = "fieldB_Sub1", value = Field.Property.CHECK)
		public boolean hasFieldB_Sub1() {
			return true;
		}

		/**
		 * Field b_ sub1 length.
		 * 
		 * @return the int
		 */
		@Dynamic(field = "fieldB_Sub1", value = Field.Property.LENGTH)
		public int fieldB_Sub1Length() {
			return 1;
		}

		/**
		 * Field b_ sub1.
		 * 
		 * @return the int
		 */
		@Field(parent = "fieldB", offset = 0)
		public int fieldB_Sub1() {
			return getUByte(12);
		}
	}

	/**
	 * The Class TestSubHeader.
	 */
	@Header(length = 40, id = 0)
	public static class TestSubHeader extends JHeader {

		/**
		 * The Class Sub1.
		 */
		@Header(length = 30)
		public static class Sub1 extends JSubHeader<TestSubHeader> {

			/**
			 * The Class Sub2.
			 */
			public static class Sub2 extends Sub1 {

				/**
				 * The Class Sub3.
				 */
				@Header(id = 1)
				public static class Sub3 extends Sub2 {

					/**
					 * Len.
					 * 
					 * @param buffer
					 *          the buffer
					 * @param offset
					 *          the offset
					 * @return the int
					 */
					@HeaderLength
					public static int len(JBuffer buffer, int offset) {
						return 01;
					}
				}
			}
		}
	}

	/**
	 * Test2.
	 */
	public void test2() {

		AnnotatedHeader ah1 =
				AnnotatedHeader.inspectJHeaderClass(TestSubHeader.Sub1.Sub2.Sub3.class,
						errors);

		AnnotatedHeader ah2 =
				AnnotatedHeader.inspectJHeaderClass(TestSubHeader.Sub1.Sub2.Sub3.class,
						errors);

		assertTrue(ah1 == ah2); // Check if cached properly

	}

	/**
	 * Test with my header.
	 */
	public void testWithMyHeader() {
		@SuppressWarnings("unused")
		AnnotatedHeader ah1 =
				AnnotatedHeader.inspectJHeaderClass(MyHeader.class, errors);

	}

	/**
	 * Test ip4.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testIp4() throws IOException {
		AnnotatedHeader ah1 =
				AnnotatedHeader.inspectJHeaderClass(Ip4.class, errors);

		AnnotatedField[] afs = ah1.getFields();
		JField[] fields = AnnotatedJField.fromAnnotatedFields(afs);

		for (JField field : fields) {
			System.out.printf("field=%s\n", field.toString());
		}

		Ip4 ip = new Ip4();

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		if (packet.hasHeader(JProtocol.IP4_ID)) {
			ip = packet.getHeader(ip);
			JFormatter out = new TextFormatter(System.out);
			out.format(ip, Detail.MULTI_LINE_FULL_DETAIL);
		}

	}
}
