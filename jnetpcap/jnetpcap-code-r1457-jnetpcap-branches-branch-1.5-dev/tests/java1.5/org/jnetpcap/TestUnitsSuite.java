/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/**
 * The Class TestUnitsSuite.
 *
 * @author Sly Technologies Inc.
 */
@SuiteClasses({
		TestMetricUnitsDoubleValues.class,
		TestMetricUnitsLongValues.class,
		TestBinaryUnitsLongValues.class,
		TestBinaryUnitsDoubleValues.class,
})
@RunWith(Suite.class)
public class TestUnitsSuite {

}
