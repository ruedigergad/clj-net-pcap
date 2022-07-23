/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap;

import org.jnetpcap.util.MetricUnit;
import org.junit.Assert;
import org.junit.Test;

// TODO: Auto-generated Javadoc
/**
 * The Class TestMetricUnitsDoubleValues.
 *
 * @author Sly Technologies Inc.
 */
public class TestMetricUnitsDoubleValues {

	/**
	 * Metric none to none double.
	 */
	@Test
	public void metric_none_to_none_double() {
		Assert.assertEquals(1., MetricUnit.BYTE.convert(1., MetricUnit.BYTE), 0);
	}

	/**
	 * Metric kilo to none double.
	 */
	@Test
	public void metric_Kilo_to_none_double() {
		Assert.assertEquals(1000., MetricUnit.BYTE.convert(1., MetricUnit.KILOBYTE), 0);
	}

	/**
	 * Metric mega to kilo double.
	 */
	@Test
	public void metric_mega_to_kilo_double() {
		Assert.assertEquals(1000., MetricUnit.KILOBYTE.convert(1., MetricUnit.MEGABYTE), 0);
	}

	/**
	 * Metric zetta to mega double.
	 */
	@Test
	public void metric_zetta_to_mega_double() {
		Assert.assertEquals(1000000000000000., MetricUnit.MEGABYTE.convert(1., MetricUnit.ZETTABYTE), 0);
	}

	/**
	 * Metric kilo to mega double.
	 */
	@Test
	public void metric_kilo_to_mega_double() {
		Assert.assertEquals(1., MetricUnit.MEGABYTE.convert(1000., MetricUnit.KILOBYTE), 0);
	}

	/**
	 * Metric sub milli to none double.
	 */
	@Test
	public void metric_sub_bytes_to_kilos_double() {
		Assert.assertEquals(0., MetricUnit.KILOBYTE.convert(999., MetricUnit.BYTE), 0);
	}

}
