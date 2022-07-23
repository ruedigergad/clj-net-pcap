/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap.util;

/**
 * A {@code UnitPrefix} represents a metric or a binary prefix unit of a given *
 * granularity and provides utility methods to convert across different unit
 * prefixes. A {@code UnitPrefix} does not maintain length information, but only
 * helps organize and use length representations that may be maintained
 * separately across various contexts.
 * 
 * <p>
 * Since jNetpcap deals potentially with large length values prone to 32-bit
 * integer value wrap, typically in mega bytes or mega bits, and up to tera
 * bytes and tera bits, the {@code UnitPrefix} interface and its enum table
 * implementations comee in handy in conveying those large values.
 * <p>
 *
 * @author Sly Technologies Inc.
 */
public interface UnitPrefix {

	/**
	 * Checks if unit is a binary prefix or power of 1024.
	 *
	 * @return true, if is binary, otherwise metric
	 */
	public boolean isBinary();

	/**
	 * Checks if the unit is in bytes. For example, {@link BinaryUnit#KILOBYTE}
	 * will return true and {@link BinaryUnit#KILOBIT} will return false.
	 *
	 * @return true, if the unit is in bytes otherwise false if it is in bits
	 */
	public boolean isInBytes();

	/**
	 * To bytes.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toBytes(long value);

	/**
	 * To bits.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toBits(long value);

	/**
	 * Convert the given unit prefix source in the given unit to this unit.
	 * Conversions from finer to coarser granularities truncate, so lose
	 * precision. For example converting 999 kilo to mega results in 0.
	 * Conversions from coarser to finer granularities with arguments that would
	 * numerically overflow saturate to Long.MIN_VALUE if negative or
	 * Long.MAX_VALUE if positive. For example, to convert 10 giga to kilo, use:
	 * MetricUnit.KILOBYTE.convert(10L, TimeUnit.GIGA)
	 *
	 * @param source
	 *            the source value
	 * @param sourceUnit
	 *            the source unit
	 * @return the long
	 */
	public long convert(long source, UnitPrefix sourceUnit);

	/**
	 * Convert.
	 *
	 * @param source
	 *            the source value
	 * @param sourceUnit
	 *            the source unit
	 * @return the double
	 */
	public double convert(double source, UnitPrefix sourceUnit);

	/**
	 * Prefix.
	 *
	 * @return the int
	 */
	public int prefix();

	/**
	 * Base.
	 *
	 * @return the int
	 */
	public int base();

	/**
	 * Bit shift for unit. For a BIT unit type bit shift is 3 and for byte unit
	 * type bit shift is 0. That is to calculate number of bits we need to
	 * perform an additional {@code 1 << 3} shift after calculating number of
	 * bytes.
	 *
	 * @return the number of bits to shift
	 */
	public int shift();

	/**
	 * Symbol.
	 *
	 * @return the string
	 */
	public String symbol();
}
