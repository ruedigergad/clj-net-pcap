/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011 Sly Technologies, Inc.
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
package org.jnetpcap.protocol.tcpip.radius;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.format.JFormatter.Style;
import org.jnetpcap.packet.structure.DefaultJField;

public class RadiusAVPField extends DefaultJField {

	/** An empty string. */
	public final static String EMPTY = "";

	public RadiusAVPField(String name, int offset, int length) {
		super(name, offset * 8, length * 8);
	}

	public RadiusAVPField(String name, int avpType, int offset, int length,
			Object value, String valueDescription) {
		super(name, offset * 8, length * 8);
		this.avpType = avpType;
		setValue(value);
		setStyle(Style.INT_DEC);
		setValue(valueDescription);
	}

	public RadiusAVPField(String name, int avpType, int offset, int length,
			Object value, Style style) {
		super(name, offset * 8, length * 8);

		this.avpType = avpType;
		setValue(value);
		setStyle(style);
		setValue(value);
	}

	public RadiusAVPField(String name, int avpType, int offset, int length,
			Object value, Style style, String valueDescription) {
		super(name, offset * 8, length * 8);

		this.avpType = avpType;
		setValue(value);
		setStyle(style);
		setValue(valueDescription);
	}

	private int avpType;

	/**
	 * @param header
	 * @return
	 * @see org.jnetpcap.packet.structure.JField#getDisplay(org.jnetpcap.packet.JHeader)
	 */
	@Override
	public String getDisplay(JHeader header) {
		return fixupAVPName(getName());
	}

	private String fixupAVPName(String str) {
		return str.replace('_', '-');

	}

	@Override
	public String toString() {
		return String.format("name=%s(%d), len=%d, value=%s\n",
				getName(),
				avpType,
				getLength(null) / 8,
				getValue(null).toString());
	}

	/**
	 * @return the avpType
	 */
	public int getAvpType() {
		return avpType;
	}

	/**
	 * @param avpType
	 *          the avpType to set
	 */
	public void setAvpType(int avpType) {
		this.avpType = avpType;
	}
}
