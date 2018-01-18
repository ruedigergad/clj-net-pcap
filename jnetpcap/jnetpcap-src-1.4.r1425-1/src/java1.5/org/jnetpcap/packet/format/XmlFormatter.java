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
package org.jnetpcap.packet.format;

import java.io.IOException;
import java.sql.Timestamp;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.structure.JField;

// TODO: Auto-generated Javadoc
/**
 * This formatter products XML output for a packet. A packet content is output
 * as XML sheet based on field objects read from each header within a packet.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class XmlFormatter extends JFormatter {

	/** The Constant PAD. */
	private static final String PAD = "  ";

	/** The Constant LT. */
	private static final String LT = "<";

	/** The Constant GT. */
	private static final String GT = ">";

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#end(org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JField,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param field
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#fieldAfter(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.structure.JField, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void fieldAfter(JHeader header, JField field, Detail detail)
			throws IOException {

		if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {
			decLevel();
			pad().format(LT + "/hexdump" + GT + "\n");
		} /*
			 * else if (false && field.hasSubFields()) { final String v =
			 * stylizeSingleLine(header, field, field.getValue(header));
			 * 
			 * pad().format(LT + "/field" + GT);
			 * 
			 * }
			 */else if (field.getStyle() == Style.INT_BITS) {
		}

		decLevel();
	}

	/**
	 * Instantiates a new xml formatter.
	 */
	public XmlFormatter() {
		super();
	}

	/**
	 * Instantiates a new xml formatter.
	 * 
	 * @param out
	 *          the out
	 */
	public XmlFormatter(Appendable out) {
		super(out);
	}

	/**
	 * Instantiates a new xml formatter.
	 * 
	 * @param out
	 *          the out
	 */
	public XmlFormatter(StringBuilder out) {
		super(out);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#start(org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JField,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param field
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#fieldBefore(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.structure.JField, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void fieldBefore(JHeader header, JField field, Detail detail)
			throws IOException {

		incLevel(PAD);

		if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {
			pad().format(LT + "hexdump offset=\"%d\" length=\"%d\"" + GT,
					field.getOffset(header),
					field.getLength(header));
			incLevel(PAD);

			final String[] v =
					stylizeMultiLine(header,
							field,
							Style.BYTE_ARRAY_HEX_DUMP_NO_TEXT,
							field.getValue(header));

			incLevel(PAD);
			for (String i : v) {
				pad().format(LT + "hexline data=\"%s\"/" + GT, i.trim());
			}

			decLevel();

		} /*
			 * else if (false && field.hasSubFields()) { final String v =
			 * stylizeSingleLine(header, field, field.getValue(header));
			 * 
			 * pad().format( LT +
			 * "field name=\"%s\" value=\"%s\" offset=\"%d\" length=\"%d\"" + GT,
			 * field.getName(), v, field.getOffset(header), field.getLength(header));
			 * 
			 * }
			 */else if (field.getStyle() == Style.INT_BITS) {
		} else if (field.getStyle() == Style.BYTE_ARRAY_ARRAY_IP4_ADDRESS) {
			byte[][] table = (byte[][]) field.getValue(header);

			for (byte[] b : table) {
				final String v = stylizeSingleLine(header, field, b);
				pad().format(LT + "ip4=\"%s\" /" + GT, v);
			}

			incLevel(0); // Inc for multi line fields
		} else {
			final String v = stylizeSingleLine(header, field, field.getValue(header));

			pad().format(LT
					+ "field name=\"%s\" value=\"%s\" offset=\"%d\" length=\"%d\"/" + GT,
					field.getName(),
					v,
					field.getOffset(header),
					field.getLength(header));
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#end(org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#headerAfter(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerAfter(JHeader header, Detail detail) throws IOException {

		pad().format(LT + "/header" + GT);
		pad();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#start(org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#headerBefore(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerBefore(JHeader header, Detail detail) throws IOException {
		pad().format(LT + "header name=\"%s\"", header.getName());
		incLevel(PAD + PAD);

		pad().format("nicname=\"%s\"", header.getNicname());
		pad().format("classname=\"%s\"", header.getClass().getCanonicalName());
		pad().format("offset=\"%d\"", header.getOffset());
		pad().format("length=\"%d\"" + GT, header.getLength());
		decLevel();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#packetAfter(org.jnetpcap.packet.JPacket
	 * , org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param packet
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#packetAfter(org.jnetpcap.packet.JPacket, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetAfter(JPacket packet, Detail detail) throws IOException {

		decLevel();
		pad().format(LT + "/packet" + GT);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#packetBefore(org.jnetpcap.packet.
	 * JPacket, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param packet
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#packetBefore(org.jnetpcap.packet.JPacket, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetBefore(JPacket packet, Detail detail) throws IOException {
		pad().format(LT + "packet");

		incLevel(PAD + PAD);

		pad().format("wirelen=\"%d\"", packet.getCaptureHeader().wirelen());
		pad().format("caplen=\"%d\"", packet.getCaptureHeader().caplen());

		if (frameIndex != -1) {
			pad().format("index=\"%d\"", frameIndex);
		}

		pad().format("timestamp=\"%s\"",
				new Timestamp(packet.getCaptureHeader().timestampInMillis()));
		pad().format("captureSeconds=\"%s\"", packet.getCaptureHeader().seconds());
		pad().format("captureNanoSeconds=\"%s\"" + GT,
				packet.getCaptureHeader().nanos());
		pad();

		decLevel();

		incLevel(PAD);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#subHeaderAfter(org.jnetpcap.packet
	 * .JHeader, org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param subHeader
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#subHeaderAfter(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.JHeader, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void subHeaderAfter(JHeader header, JHeader subHeader, Detail detail)
			throws IOException {

		headerAfter(subHeader, detail);
		decLevel();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#subHeaderBefore(org.jnetpcap.packet
	 * .JHeader, org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param subHeader
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#subHeaderBefore(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.JHeader, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void subHeaderBefore(JHeader header,
			JHeader subHeader,
			Detail detail) throws IOException {

		incLevel(PAD);
		pad();

		headerBefore(subHeader, detail);
	}

}
