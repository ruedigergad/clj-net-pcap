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
package org.jnetpcap.util;

// TODO: Auto-generated Javadoc
/**
 * A utility class that facilitates taking measurements and reports.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class LongCounter {

	/** The counter. */
	private long counter;

	/** The total. */
	private long total;
	
	/** The units. */
	final private String units;
	
	/** The u. */
	final private String u;
	
	/**
	 * Instantiates a new long counter.
	 * 
	 * @param units
	 *          the units
	 * @param u
	 *          the u
	 */
	public LongCounter(String units, String u) {
		this.units = units;
		this.u = u;
		
		reset();
	}

	/**
	 * Instantiates a new long counter.
	 * 
	 * @param units
	 *          the units
	 */
	public LongCounter(String units) {
		this(units, "" + units.charAt(0));
	}
	
	/**
	 * Instantiates a new long counter.
	 */
	public LongCounter() {
		this("bytes");
	}

	/**
	 * Snapshot baseline.
	 */
	public void snapshotBaseline() {
		// Empty
	}

	/**
	 * Initializes the test to its defaults
	 */
	public void reset() {
		this.counter = 0;
		this.total = 0;
	}

	/**
	 * Takes a measurment snapshot and updates its counters. This is where
	 * measurement calculations stem from such as packet rates or bit rates.
	 */
	public void snapshot() {
		this.counter = 0;
	}

	/**
	 * Inc.
	 * 
	 * @param delta
	 *          the delta
	 */
	public void inc(long delta) {
		counter += delta;
		total += delta;
	}
	
	/**
	 * Sets the.
	 * 
	 * @param value
	 *          the value
	 */
	public void set(long value) {
		counter = value;
		total = value;
	}

	/**
	 * Counter.
	 * 
	 * @return the long
	 */
	public long counter() {
		return this.counter;
	}

	/**
	 * Total.
	 * 
	 * @return the long
	 */
	public long total() {
		return this.total;
	}
	
	/**
	 * Units.
	 * 
	 * @return the string
	 */
	public String units() {
		return this.units;
	}
	
	/**
	 * U.
	 * 
	 * @return the string
	 */
	public String u() {
		return this.u;
	}

}
