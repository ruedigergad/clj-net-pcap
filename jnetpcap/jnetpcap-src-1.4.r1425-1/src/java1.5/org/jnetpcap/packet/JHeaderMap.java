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
package org.jnetpcap.packet;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.JField;

// TODO: Auto-generated Javadoc
/**
 * The Class JHeaderMap.
 * 
 * @param <B>
 *          header baseclass that all sub-header's should be enclosed in
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JHeaderMap<B extends JHeader>
    extends JHeader implements JCompoundHeader<B> {

	/** The Constant MAX_HEADERS. */
	public final static int MAX_HEADERS = 64;

	/** The options bitmap. */
	protected long optionsBitmap = -1;

	/** The options offsets. */
	protected int[] optionsOffsets = new int[MAX_HEADERS];

	/** The options length. */
	protected int[] optionsLength = new int[MAX_HEADERS];

	/** The X_ headers. */
	protected final JHeader[] X_HEADERS = new JHeader[MAX_HEADERS];

	/**
	 * Instantiates a new j header map.
	 */
	public JHeaderMap() {
		super();

		/*
		 * Create sub-header instances using default constructor from annotation
		 */
		reorderAndSave(createHeaderInstances(annotatedHeader.getHeaders()));
	}

	/**
	 * Creates the header instances.
	 * 
	 * @param headers
	 *          the headers
	 * @return the j header[]
	 */
	private static JHeader[] createHeaderInstances(AnnotatedHeader... headers) {
		JHeader[] h = new JHeader[headers.length];

		for (int i = 0; i < h.length; i++) {
			h[i] = createHeaderInstance(headers[i]);
		}

		return h;
	}

	/**
	 * Creates the header instance.
	 * 
	 * @param header
	 *          the header
	 * @return the j header
	 */
	private static JHeader createHeaderInstance(AnnotatedHeader header) {
		try {
			return header.getHeaderClass().newInstance();
		} catch (InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Instantiates a new j header map.
	 * 
	 * @param id
	 *          the id
	 * @param fields
	 *          the fields
	 * @param name
	 *          the name
	 * @param nicname
	 *          the nicname
	 * @param unordered
	 *          the unordered
	 */
	public JHeaderMap(int id, JField[] fields, String name, String nicname,
	    JHeader[] unordered) {
		super(id, fields, name, nicname);

		reorderAndSave(unordered);
	}

	/**
	 * Instantiates a new j header map.
	 * 
	 * @param id
	 *          the id
	 * @param name
	 *          the name
	 * @param unordered
	 *          the unordered
	 */
	public JHeaderMap(int id, String name, JHeader[] unordered) {
		super(id, name);
		reorderAndSave(unordered);
	}

	/**
	 * Instantiates a new j header map.
	 * 
	 * @param id
	 *          the id
	 * @param name
	 *          the name
	 * @param nicname
	 *          the nicname
	 * @param unordered
	 *          the unordered
	 */
	public JHeaderMap(int id, String name, String nicname, JHeader[] unordered) {
		super(id, name, nicname);
		reorderAndSave(unordered);
	}

	/**
	 * Sets the sub headers.
	 * 
	 * @param headers
	 *          the new sub headers
	 * @see org.jnetpcap.packet.JHeader#setSubHeaders(org.jnetpcap.packet.JHeader[])
	 */
	@Override
	public void setSubHeaders(JHeader[] headers) {
		reorderAndSave(headers);
	}

	/**
	 * Gets the sub header.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param header
	 *          the header
	 * @return the sub header
	 * @see org.jnetpcap.packet.JCompoundHeader#getSubHeader(org.jnetpcap.packet.JSubHeader)
	 */
	public <T extends JSubHeader<B>> T getSubHeader(T header) {

		final int offset = optionsOffsets[header.getId()];
		final int length = optionsLength[header.getId()];
		header.peer(this, offset, length);
		header.setOffset(offset);
		header.setLength(length);
		header.setParent(this);
		header.packet = this.packet;

		return header;
	}

	/**
	 * Gets the sub header.
	 * 
	 * @param header
	 *          the header
	 * @return the sub header
	 */
	@SuppressWarnings("unchecked")
	private JHeader getSubHeader(JHeader header) {

		JSubHeader<B> sub = (JSubHeader<B>) header;

		final int id = sub.getId();
		final int offset = optionsOffsets[id];
		final int length = optionsLength[id];
		sub.peer(this, offset, length);
		sub.setOffset(offset);
		sub.setLength(length);
		sub.setParent(this);

		return header;
	}

	/**
	 * Gets the sub headers.
	 * 
	 * @return the sub headers
	 * @see org.jnetpcap.packet.JHeader#getSubHeaders()
	 */
	public JHeader[] getSubHeaders() {
		List<JHeader> headers = new ArrayList<JHeader>();
		for (int i = 0; i < MAX_HEADERS; i++) {
			if (hasSubHeader(i) && X_HEADERS[i] != null) {
				JHeader header = X_HEADERS[i];
				getSubHeader(header);
				headers.add(X_HEADERS[i]);
			}
		}
		return headers.toArray(new JHeader[headers.size()]);
	}

	/**
	 * Checks for sub header.
	 * 
	 * @param id
	 *          the id
	 * @return true, if successful
	 * @see org.jnetpcap.packet.JCompoundHeader#hasSubHeader(int)
	 */
	public boolean hasSubHeader(int id) {
		return (optionsBitmap & (1 << id)) > 0;
	}

	/**
	 * Checks for sub header.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param header
	 *          the header
	 * @return true, if successful
	 * @see org.jnetpcap.packet.JCompoundHeader#hasSubHeader(org.jnetpcap.packet.JSubHeader)
	 */
	public <T extends JSubHeader<B>> boolean hasSubHeader(T header) {
		if (hasSubHeader(header.getId())) {
			getSubHeader(header);

			return true;
		} else {
			return false;
		}
	}

	/**
	 * Reorder and save.
	 * 
	 * @param unordered
	 *          the unordered
	 */
	private void reorderAndSave(JHeader[] unordered) {

		for (JHeader u : unordered) {
			X_HEADERS[u.getId()] = u;
		}
	}

	/**
	 * Checks for sub headers.
	 * 
	 * @return true, if successful
	 * @see org.jnetpcap.packet.JHeader#hasSubHeaders()
	 */
	public boolean hasSubHeaders() {
		return this.optionsBitmap != 0;
	}
	
	/**
	 * Sets the sub header.
	 * 
	 * @param id
	 *          the id
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 */
	protected void setSubHeader(int id, int offset, int length) {
		this.optionsBitmap |= (1L << id);
		this.optionsLength[id] = length;
		this.optionsOffsets[id] = offset;
	}

}
