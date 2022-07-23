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

import java.io.IOException;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class RateMeasurement
    extends
    Measurement {

	/** The ts. */
	long ts;

	/** The te. */
	long te;

	/** The rate. */
	private float rate;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.Measurement#report(java.lang.Appendable)
	 */
	@Override
	public void report(Appendable out) throws IOException {
		calcRate();
		
		out.append(Float.toString(rate));
	}

	/**
	 * Calc rate.
	 */
	private void calcRate() {
		this.te = System.currentTimeMillis();

		rate = ((float) counter) / (te - ts);
	}
	
  /* (non-Javadoc)
   * @see org.jnetpcap.util.Measurement#snapshot()
   */
  public void snapshot() {
    super.snapshot();
    
  	this.ts = System.currentTimeMillis();
  	this.te = this.ts;
  }


	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.Measurement#reset()
	 */
	@Override
	public void reset() {
		this.counter = 0;
		this.total = 0;
		this.ts = System.currentTimeMillis();
		this.te = ts;
		this.rate = 0f;
	}

}
