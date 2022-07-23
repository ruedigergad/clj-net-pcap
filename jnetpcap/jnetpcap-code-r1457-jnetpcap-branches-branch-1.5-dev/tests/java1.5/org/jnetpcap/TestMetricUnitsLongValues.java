/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap;

import org.jnetpcap.util.MetricUnit;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author Sly Technologies Inc.
 *
 */
public class TestMetricUnitsLongValues {

	@Test
	public void metric_none_to_none_long() {
		Assert.assertEquals(1, MetricUnit.BYTE.convert(1, MetricUnit.BYTE));
	}

	@Test
	public void metric_Kilo_to_none_long() {
		Assert.assertEquals(1000, MetricUnit.BYTE.convert(1, MetricUnit.KILOBYTE));
	}

	@Test
	public void metric_mega_to_kilo_long() {
		Assert.assertEquals(1000, MetricUnit.KILOBYTE.convert(1, MetricUnit.MEGABYTE));
	}

	@Test
	public void metric_zetta_to_mega_long() {
		Assert.assertEquals(1000000000000000L, MetricUnit.MEGABYTE.convert(1, MetricUnit.ZETTABYTE));
	}

	/**
	 * Metric kilo to mega long.
	 */
	@Test
	public void metric_kilo_to_mega_long() {
		Assert.assertEquals(1, MetricUnit.MEGABYTE.convert(1000, MetricUnit.KILOBYTE));
	}

	@Test
	public void metric_sub_bytes_to_kilos_long() {
		Assert.assertEquals(0, MetricUnit.BYTE.toKilos(999));
	}

}
