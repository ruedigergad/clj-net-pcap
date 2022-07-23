/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap.util;

/**
 * A binary prefix is a unit prefix for multiples of units in data processing,
 * data transmission, and digital information, notably the bit and the byte, to
 * indicate multiplication by a power of 2.
 * <p>
 * The computer industry has historically used the units kilobyte, megabyte, and
 * gigabyte, and the corresponding symbols KB, MB, and GB, in at least two
 * slightly different measurement systems. In citations of main memory (RAM)
 * capacity, gigabyte customarily means 1073741824 bytes. As this is the third
 * power of 1024, and 1024 is a power of two (2<sup>10</sup>), this usage is
 * referred to as a binary measurement.
 * </p>
 * <p>
 * In most other contexts, the industry uses the multipliers kilo, mega, giga,
 * etc., in a manner consistent with their meaning in the International System
 * of Units (SI), namely as powers of 1000. For example, a 500 gigabyte hard
 * disk holds 500000000000 bytes, and a 1 Gbit/s (gigabit-per-second) Ethernet
 * connection transfers data at 1000000000 bit/s. In contrast with the binary
 * prefix usage, this use is described as a decimal prefix, as 1000 is a power
 * of 10 (10<sup>3</sup>).
 * </p>
 * 
 * @author Sly Technologies Inc.
 * @see https://en.wikipedia.org/wiki/Binary_prefix
 */
public enum BinaryUnit implements UnitPrefix {

	/** 1<sup>0</sup> */
	BYTE(0, "B"),

	/** 8<sup>1</sup> */
	BIT(3, "b"),

	/** 1024<sup>1</sup> or 1 << 10. */
	KILOBYTE(10, "KB"),

	/** 8096<sup>1</sup> or 1 << 13. */
	KILOBIT(13, "kb"),

	/** 1024<sup>2</sup> or 1 << 20. */
	MEGABYTE(20, "MB"),

	/** 8096<sup>2</sup> or 1 << 23. */
	MEGABIT(23, "mb"),

	/** 1024<sup>3</sup> or 1L << 30. */
	GIGABYTE(30, "GB"),

	/** 8096<sup>3</sup> or 1L << 33. */
	GIGABIT(33, "gb"),

	/** 1024<sup>4</sup> or 1L << 40. */
	TERABYTE(40, "T"),

	/** 8096<sup>4</sup> or 1L << 43. */
	TERABIT(43, "T"),

	/** 1024<sup>5</sup> or 1L << 50. */
	PETABYTE(50, "P"),

	/** 8096<sup>5</sup> or 1L << 53. */
	PETABIT(53, "P"),

	/** 1024<sup>6</sup> or 1L << 60. */
	EXABYTE(60, "E"),

	/** 8096<sup>6</sup> or 1L << 63. */
	EXABIT(63, "E"),

	/** 1024<sup>7</sup> or 1L << 70. */
	ZETTABYTE(70, "Z"),

	/** 8096<sup>7</sup> or 1L << 73. */
	ZETTABIT(73, "Z"),

	/** 1024<sup>8</sup> or 1L << 80. */
	YOTTABYTE(80, "Y"),

	/** 8096<sup>8</sup> or 1L << 83. */
	YOTTABIT(83, "Y"),

	;

	/** The Constant KILO_BINARY. */
	public final static int KB = (1 << 10);

	/** The Constant MEGA_BINARY. */
	public final static int MB = (1 << 20);

	/** The Constant GIGA_BINARY. */
	public final static int GB = (1 << 30);

	/** The Constant TERA_BINARY. */
	public final static long TB = (1 << 40);

	/** The Constant PETA_BINARY. */
	public final static long PB = (1 << 50);

	/** The base 2. */
	private final int base2;

	private final int shift;

	/**
	 * Instantiates a new binary unit.
	 *
	 * @param base2
	 *            the base 2
	 * @param symbol
	 *            the symbol
	 */
	BinaryUnit(int base2, String symbol) {
		this.base2 = base2;
		this.shift = (name().endsWith("BIT")) ? 3 : 0;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#shift()
	 */
	@Override
	public int shift() {
		return this.shift;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#base()
	 */
	@Override
	public int base() {
		return 2;
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
		if (delta < 0) {
			delta *= -1;
			return source >> delta;
		} else {
			return source << delta;
		}
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#isBinary()
	 */
	@Override
	public boolean isBinary() {
		return true;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#prefix()
	 */
	@Override
	public int prefix() {
		return base2;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#symbol()
	 */
	@Override
	public String symbol() {
		return this.symbol();
	}

	/**
	 * To exbis.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toExas(long source) {
		return EXABYTE.convert(source, this);
	}

	/**
	 * To gibis.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toGigas(long source) {
		return GIGABYTE.convert(source, this);
	}

	/**
	 * To kibis.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toKilos(long source) {
		return KILOBYTE.convert(source, this);
	}

	/**
	 * To mebis.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toMegas(long source) {
		return MEGABYTE.convert(source, this);
	}

	/**
	 * To pebis.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toPetas(long source) {
		return PETABYTE.convert(source, this);
	}

	/**
	 * To tebis.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toTeras(long source) {
		return TERABYTE.convert(source, this);
	}

	/**
	 * To yobis.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toYottas(long source) {
		return YOTTABYTE.convert(source, this);
	}

	/**
	 * To zebis.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toZettas(long source) {
		return ZETTABYTE.convert(source, this);
	}

	/**
	 * To bytes.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toBytes(long source) {
		return BYTE.convert(source, this);
	}

	/**
	 * To none.
	 *
	 * @param source
	 *            the source
	 * @return the long
	 */
	public long toLong(long source) {
		return BYTE.convert(source, this);
	}

	/**
	 * To int.
	 *
	 * @param source
	 *            the source
	 * @return the int
	 */
	public int toInt(long source) {
		return (int) BYTE.convert(source, this);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.jnetpcap.util.UnitPrefix#toBits(long)
	 */
	@Override
	public long toBits(long value) {
		return BIT.convert(value, this);
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
