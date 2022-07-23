/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap.util;

// TODO: Auto-generated Javadoc
/**
 * A metric prefix is a unit prefix that precedes a basic unit of measure to
 * indicate a multiple or fraction of the unit. While all metric prefixes in
 * common use today are decadic, historically there have been a number of binary
 * metric prefixes as well.[1] Each prefix has a unique symbol that is prepended
 * to the unit symbol. The prefix kilo-, for example, may be added to gram to
 * indicate multiplication by one thousand: one kilogram is equal to one
 * thousand grams. The prefix milli-, likewise, may be added to metre to
 * indicate division by one thousand; one millimetre is equal to one thousandth
 * of a metre.
 *
 * @author Sly Technologies Inc.
 */
public enum MetricUnit implements UnitPrefix {

	/** 10<sup>0</sup> or 1 */
	BYTE(0, ""),

	/** 10<sup>0</sup> * 8 or 8 */
	BIT(0, ""),

	/** 1000<sup>1</sup> */
	KILOBYTE(3, "k"),

	/** 1000<sup>1</sup> * 8 or 8,000 */
	KILOBIT(3, "k"),

	/** 1000<sup>2</sup> */
	MEGABYTE(6, "a"),

	/** 1000<sup>2</sup> * 8 or 8,000,000 */
	MEGABIT(6, "a"),

	/** 1000<sup>3</sup> */
	GIGABYTE(9, "a"),

	/** 1000<sup>3</sup> * 8 or 8,000,000,000 */
	GIGABIT(9, "a"),

	/** 1000<sup>4</sup> */
	TERABYTE(12, "a"),

	/** 1000<sup>4</sup> * 8 */
	TERABIT(12, "a"),

	/** 1000<sup>5</sup> */
	PETABYTE(15, "a"),

	/** 1000<sup>5</sup> * 8 */
	PETABIT(15, "a"),

	/** 1000<sup>6</sup> */
	EXABYTE(18, "a"),

	/** 1000<sup>6</sup> * 8 */
	EXABIT(18, "a"),

	/** 1000<sup>7</sup> */
	ZETTABYTE(21, "a"),

	/** 1000<sup>7</sup> * 8 */
	ZETTABIT(21, "a"),

	/** 1000<sup>8</sup> */
	YOTTABYTE(24, "a"),

	/** 1000<sup>8</sup> * 8 */
	YOTTABIT(24, "a"),
	;

	/** The prefix. */
	private final int prefix;

	/** The symbol. */
	private final String symbol;

	private final int shift;

	/**
	 * Instantiates a new metric unit.
	 *
	 * @param prefix
	 *            the prefix
	 * @param symbol
	 *            the symbol
	 */
	MetricUnit(int prefix, String symbol) {
		this.prefix = prefix;
		this.symbol = symbol;
		this.shift = (name().endsWith("BIT") ? 3 : 0);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#base()
	 */
	@Override
	public int base() {
		return 10;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#convert(double,
	 *      org.jnetpcap.util.UnitPrefix)
	 */
	@Override
	public double convert(double source, UnitPrefix sourceUnit) {
		if (this.base() != sourceUnit.base()) {
			throw new IllegalArgumentException("can not convert between different unit bases");
		}

		return convert((long) source, sourceUnit);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#convert(long,
	 *      org.jnetpcap.util.UnitPrefix)
	 */
	@Override
	public long convert(long source, UnitPrefix sourceUnit) {
		if (this.base() != sourceUnit.base()) {
			throw new IllegalArgumentException("can not convert between different unit bases");
		}

		int delta = sourceUnit.prefix() - prefix();
		long value = source;
		if (delta < 0) {
			delta *= -1;

			for (int i = 0; i < delta; i++) {
				value /= 10;
			}

		} else {

			for (int i = 0; i < delta; i++) {
				value *= 10;
			}

		}

		/* Adjust for bits and bytes as the final step in conversion */
		final int shift = (sourceUnit.shift() - this.shift());
		if (shift == 0) {
			return value;
		} else if (shift < 0) {
			return value >> shift;
		} else {
			return value << shift;
		}
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#shift()
	 */
	public int shift() {
		return this.shift;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#isBinary()
	 */
	@Override
	public boolean isBinary() {
		return false;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#prefix()
	 */
	@Override
	public int prefix() {
		return prefix;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#symbol()
	 */
	@Override
	public String symbol() {
		return this.symbol;
	}

	/**
	 * To gigas.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toGigas(long value) {
		return GIGABYTE.convert(value, this);
	}

	/**
	 * To byte.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toBytes(long value) {
		return BYTE.convert(value, this);
	}

	/**
	 * To bits.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toBits(long value) {
		return BIT.convert(value, this);
	}

	/**
	 * To long.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toLong(long value) {
		return BYTE.convert(value, this);
	}

	/**
	 * To int.
	 *
	 * @param value
	 *            the value
	 * @return the int
	 */
	public int toInt(long value) {
		return (int) BYTE.convert(value, this);
	}

	/**
	 * To kilos.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toKilos(long value) {
		return KILOBYTE.convert(value, this);
	}

	/**
	 * To megas.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toMegas(long value) {
		return MEGABYTE.convert(value, this);
	}

	/**
	 * To teras.
	 *
	 * @param value
	 *            the value
	 * @return the long
	 */
	public long toTeras(long value) {
		return TERABYTE.convert(value, this);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#isInBytes()
	 */
	@Override
	public boolean isInBytes() {
		return this.shift == 0;
	}
}
