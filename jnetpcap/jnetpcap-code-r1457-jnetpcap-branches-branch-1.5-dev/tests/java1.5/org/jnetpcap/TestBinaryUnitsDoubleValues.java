/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap;

import org.jnetpcap.util.BinaryUnit;
import org.junit.Assert;
import org.junit.Test;

// TODO: Auto-generated Javadoc
/**
 * The Class TestBinaryUnitsDoubleValues.
 *
 * @author Sly Technologies Inc.
 */
public class TestBinaryUnitsDoubleValues {

	/**
	 * Binary none to none long.
	 */
	@Test
	public void binary_none_to_none_long() {
		Assert.assertEquals(1., BinaryUnit.BYTE.convert(1., BinaryUnit.BYTE), 0);
	}

	/**
	 * Binary kibi to none long.
	 */
	@Test
	public void binary_Kibi_to_none_long() {
		Assert.assertEquals(1024., BinaryUnit.BYTE.convert(1., BinaryUnit.KILOBYTE), 0);
	}

	/**
	 * Binary mebi to kibi long.
	 */
	@Test
	public void binary_mebi_to_kibi_long() {
		Assert.assertEquals(1024., BinaryUnit.KILOBYTE.convert(1., BinaryUnit.MEGABYTE), 0);
	}

	/**
	 * Binary zebi to mebi long.
	 */
	@Test
	public void binary_zebi_to_mebi_long() {
		Assert.assertEquals(1024. * 1024. * 1024. * 1024. * 1024., BinaryUnit.MEGABYTE.convert(1., BinaryUnit.ZETTABYTE), 0);
	}

	/**
	 * Binary kibi to mebi long.
	 */
	@Test
	public void binary_kibi_to_mebi_long() {
		Assert.assertEquals(1., BinaryUnit.MEGABYTE.convert(1024., BinaryUnit.KILOBYTE), 0);
	}

	/**
	 * Binary sub none to kibi long.
	 */
	@Test
	public void binary_sub_none_to_kibi_long() {
		Assert.assertEquals(0., BinaryUnit.KILOBYTE.convert(1023., BinaryUnit.BYTE), 0);
	}

}
