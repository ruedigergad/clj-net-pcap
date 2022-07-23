/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap;

import org.jnetpcap.util.BinaryUnit;
import org.junit.Assert;
import org.junit.Test;

// TODO: Auto-generated Javadoc
/**
 * The Class TestBinaryUnitsLongValues.
 *
 * @author Sly Technologies Inc.
 */
public class TestBinaryUnitsLongValues {

	/**
	 * Binary none to none long.
	 */
	@Test
	public void binary_none_to_none_long() {
		Assert.assertEquals(1, BinaryUnit.BYTE.convert(1, BinaryUnit.BYTE));
	}

	/**
	 * Binary kibi to none long.
	 */
	@Test
	public void binary_kilo_to_none_long() {
		Assert.assertEquals(1024, BinaryUnit.BYTE.convert(1, BinaryUnit.KILOBYTE));
	}

	/**
	 * Binary mebi to kibi long.
	 */
	@Test
	public void binary_mega_to_kilo_long() {
		Assert.assertEquals(1024, BinaryUnit.KILOBYTE.convert(1, BinaryUnit.MEGABYTE));
	}

	/**
	 * Binary zebi to mebi long.
	 */
	@Test
	public void binary_zetta_to_mega_long() {
		Assert.assertEquals(1024L * 1024L * 1024L * 1024L * 1024L,
				BinaryUnit.MEGABYTE.convert(1, BinaryUnit.ZETTABYTE));
	}

	/**
	 * Binary kibi to mebi long.
	 */
	@Test
	public void binary_kilo_to_mega_long() {
		Assert.assertEquals(1, BinaryUnit.MEGABYTE.convert(1024, BinaryUnit.KILOBYTE));
	}

	/**
	 * Binary sub none to kibi long.
	 */
	@Test
	public void binary_sub_none_to_kilo_long() {
		Assert.assertEquals(0, BinaryUnit.BYTE.toKilos(1023));
	}

}
