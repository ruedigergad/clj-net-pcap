/**
 * Copyright (C) 2007 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap.examples.simplesniffer;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class IntRate {
	private AtomicInteger value = new AtomicInteger();
	private int tstamp;
	private final String unit;
	private final String abbr;
	private final int k;
	
	/**
	 * 
	 * @param unit label such as bytes or bits
	 * @param abbr abbreviated label such as b, p
	 * @param k what is a kilo, is it a 1000, or 1024
	 */
	public IntRate(String unit, String abbr, int k) {
		this.unit = unit;
		this.abbr = abbr;
		this.k = k;
		
		reset();
	}
	
	public int delta(int delta) {
		return value.addAndGet(delta);
	}
	
	public void reset() {
		value.set(0);
		tstamp = (int) (System.currentTimeMillis() / 1000);
	}
	
	public boolean isEmpty() {
		return value.get() == 0;
	}
	
	StringBuilder sb = new StringBuilder();
	public String toString() {
		
		sb.setLength(0);
		
		String s;
		
		if ( (s = calc(k * k * k, "g" + abbr + "ps")) != null ) {
		} else if ( (s = calc(k * k, "m" + abbr + "ps")) != null ) {
		} else if ( (s = calc(k, "k" + abbr + "ps")) != null ) {
		} else if ( (s = calc(1, unit + "/s")) != null ) {
		} else {
			return "";
		}
		
		return s;
	}
	
	private int getTimedelta() {
		return (int) (System.currentTimeMillis() / 1000 - tstamp);
	}
	
	StringBuilder cb = new StringBuilder();
	private String calc(int base, String units) {
		double rate = (double)value.get() / ((double) base / (double)getTimedelta());

		
		if (rate < 1 && base != 1) {
			return null;
		}
		
		cb.setLength(0);
		cb.append(' ');
		cb.append(rate).append(' ').append(units);
		
		return cb.toString();
		
	}

}
