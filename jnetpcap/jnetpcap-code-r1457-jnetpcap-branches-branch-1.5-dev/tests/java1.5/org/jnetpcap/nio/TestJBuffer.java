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
package org.jnetpcap.nio;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import junit.framework.TestCase;

import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.PeeringException;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class TestJBuffer
    extends TestCase {

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#getByteArray(int, byte[])}.
	 * @throws PeeringException 
	 */
	public final void testGetByteArrayIntByteArray() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	byte[] sa = new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    10,
  	    11,
  	    12,
  	    13,
  	    3,
  	    (byte) 0xbb };
  	src.put(sa);
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	byte[] array = new byte[8];
  	
  	assertEquals(8, peer.getByteArray(0, array).length);
  	assertTrue(Arrays.equals(sa, array));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#getByteArray(int, int)}.
	 * @throws PeeringException 
	 */
	public final void testGetByteArrayIntInt() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	byte[] sa = new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    10,
  	    11,
  	    12,
  	    13,
  	    3,
  	    (byte) 0xbb };
  	src.put(sa);
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	byte[] array = peer.getByteArray(0, sa.length);
  	
  	assertEquals(8, array.length);
  	assertTrue(Arrays.equals(sa, array));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#isReadonly()}.
	 * @throws PeeringException 
	 */
	public final void testIsReadonly() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	byte[] sa = new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    10,
  	    11,
  	    12,
  	    13,
  	    3,
  	    (byte) 0xbb };
  	src.put(sa);
  	src.flip();
  	src = src.asReadOnlyBuffer();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  	assertTrue(peer.isReadonly());
  
  	byte[] array = peer.getByteArray(0, sa.length);
  	
  	assertEquals(8, array.length);
  	assertTrue(Arrays.equals(sa, array));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#order()}.
	 */
	public final void testOrder() {
		JBuffer b = new JBuffer(Type.POINTER);
		
		assertEquals(ByteOrder.nativeOrder(), b.order());
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#order(java.nio.ByteOrder)}.
	 */
	public final void testOrderByteOrder() {
		JBuffer b = new JBuffer(Type.POINTER);

		b.order(ByteOrder.BIG_ENDIAN);
		assertEquals(ByteOrder.BIG_ENDIAN, b.order());
		
		b.order(ByteOrder.LITTLE_ENDIAN);
		assertEquals(ByteOrder.LITTLE_ENDIAN, b.order());
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setByte(int, byte)}.
	 * @throws PeeringException 
	 */
	public final void testSetByte() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(4, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	peer.setByte(0, (byte) 10);
  	assertEquals(src.get(0), peer.getByte(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setByteArray(int, byte[])}.
	 * @throws PeeringException 
	 */
	public final void testSetByteArray() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.clear();

  	byte[] sa = new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    10,
  	    11,
  	    12,
  	    13,
  	    3,
  	    (byte) 0xbb };
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	peer.setByteArray(0, sa);
  	
  	byte[] array = new byte[8];
  	
  	src.get(array);
  	assertTrue(Arrays.equals(sa, array));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setDouble(int, double)}.
	 * @throws PeeringException 
	 */
	public final void testSetDouble() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.clear();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  	peer.setDouble(0, 10e32f);
  
  	assertEquals(src.getDouble(0), peer.getDouble(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getDouble(0), peer.getDouble(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setFloat(int, float)}.
	 * @throws PeeringException 
	 */
	public final void testSetFloat() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  	src.clear();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(4, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  	peer.setFloat(0, 10e32f);
  
  	assertEquals(src.getFloat(0), peer.getFloat(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getFloat(0), peer.getFloat(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setInt(int, int)}.
	 * @throws PeeringException 
	 */
	public final void testSetInt() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  	src.clear();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(4, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  	peer.setInt(0, 10);
  
  	assertEquals(src.getInt(0), peer.getInt(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getInt(0), peer.getInt(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setLong(int, long)}.
	 * @throws PeeringException 
	 */
	public final void testSetLong() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.clear();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  	peer.setLong(0, 10);
  
  	assertEquals(src.getLong(0), peer.getLong(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getLong(0), peer.getLong(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setShort(int, short)}.
	 * @throws PeeringException 
	 */
	public final void testSetShort() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.clear();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  	peer.setShort(0, (short) 10);
  
  	assertEquals(src.getShort(0), peer.getShort(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getShort(0), peer.getShort(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setUByte(int, int)}.
	 * @throws PeeringException 
	 */
	public final void testSetUByte() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.clear();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  	peer.setUByte(0, 10);
  
  	assertEquals(src.get(0), peer.getUByte(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.get(0), peer.getUByte(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setUInt(int, long)}.
	 * @throws PeeringException 
	 */
	public final void testSetUInt() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.clear();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  	peer.setUInt(0, 10);
  
  	assertEquals(src.getInt(0), peer.getUInt(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getInt(0), peer.getUInt(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#setUShort(int, int)}.
	 * @throws PeeringException 
	 */
	public final void testSetUShort() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.clear();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  	peer.setUShort(0, 10);
  
  	assertEquals(src.getShort(0), peer.getUShort(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getShort(0), peer.getUShort(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#transferTo(org.jnetpcap.nio.JBuffer)}.
	 */
	public final void testTransferToJBuffer() {
		JBuffer src = new JBuffer(8);
		JBuffer dst = new JBuffer(8);
		
  	byte[] sa = new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    10,
  	    11,
  	    12,
  	    13,
  	    3,
  	    (byte) 0xbb };
  
  	src.setByteArray(0, sa);
  	
  	src.transferTo(dst);
  	
  	assertTrue(Arrays.equals(sa, dst.getByteArray(0, 8)));
	}

	/**
	 * Test method for {@link org.jnetpcap.nio.JBuffer#transferTo(org.jnetpcap.nio.JBuffer, int, int, int)}.
	 */
	public final void testTransferToJBufferIntIntInt() {
		JBuffer src = new JBuffer(8);
		JBuffer dst = new JBuffer(8);
		
  	byte[] sa = new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    10,
  	    11,
  	    12,
  	    13,
  	    3,
  	    (byte) 0xbb };
  
  	src.setByteArray(0, sa);
  	
  	src.transferTo(dst, 2, 4, 4);
  	
  	assertTrue(Arrays.equals(new byte[] {10,11,12,13}, dst.getByteArray(4, 4)));
	}

	/**
	 * Test j buffer byte.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferByte() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  	src.put(new byte[] {
  	    1,
  	    2,
  	    3,
  	    4 });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(4, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(src.get(0), peer.getByte(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.get(0), peer.getByte(0));
  }

	/**
	 * Test j buffer short.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferShort() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  	src.put(new byte[] {
  	    1,
  	    2,
  	    3,
  	    4 });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(4, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(src.getShort(0), peer.getShort(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getShort(0), peer.getShort(0));
  }

	/**
	 * Test j buffer int.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferInt() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  	src.put(new byte[] {
  	    1,
  	    2,
  	    3,
  	    4 });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(4, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(src.getInt(0), peer.getInt(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getInt(0), peer.getInt(0));
  }

	/**
	 * Test j buffer long.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferLong() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.put(new byte[] {
  	    1,
  	    2,
  	    3,
  	    4,
  	    5,
  	    6,
  	    7,
  	    8 });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(src.getLong(0), peer.getLong(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getLong(0), peer.getLong(0));
  }

	/**
	 * Test j buffer u byte.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferUByte() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  	src.put(new byte[] {
  	    (byte) 0xaa,
  	    (byte) 0xbb });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(2, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(0xaa, peer.getUByte(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(0xaa, peer.getUByte(0));
  }

	/**
	 * Test j buffer u short.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferUShort() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  	src.put(new byte[] {
  	    (byte) 0xaa,
  	    (byte) 0xbb });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(2, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(0xbbaa, peer.getUShort(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(0xaabb, peer.getUShort(0));
  }

	/**
	 * Test j buffer u int.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferUInt() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(4);
  	src.put(new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    3,
  	    (byte) 0xbb });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(4, peer.size());
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(0xbb0302aaL, peer.getUInt(0));
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(0xaa0203bbL, peer.getUInt(0));
  }

	/**
	 * Test j buffer getter bounds.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferGetterBounds() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.put(new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    3,
  	    (byte) 0xbb,
  	    1,
  	    2,
  	    3,
  	    4 });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  
  	try {
  		peer.getByte(-1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getShort(-1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getInt(-1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getLong(-1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getUByte(-1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  	try {
  		peer.getUShort(-1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getUInt(-1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getByte(8);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getShort(7);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getInt(5);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getLong(1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getUInt(-1);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getUByte(8);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getUShort(7);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  
  	try {
  		peer.getUInt(5);
  		fail("Underflow exception expected");
  	} catch (BufferUnderflowException e) {
  
  	}
  }

	/**
	 * Test j buffer float.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferFloat() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
  	src.put(new byte[] {
  	    (byte) 0xaa,
  	    2,
  	    10,
  	    11,
  	    12,
  	    13,
  	    3,
  	    (byte) 0xbb });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	peer.peer(src);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  
  	assertEquals(src.getFloat(0), peer.getFloat(0));
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(src.getFloat(0), peer.getFloat(0));
  }

	/**
	 * Test j buffer double.
	 * 
	 * @throws PeeringException
	 *           the peering exception
	 */
	public void testJBufferDouble() throws PeeringException {
  	ByteBuffer src = ByteBuffer.allocateDirect(8);
//  	src.put(new byte[] {
//  	    (byte) 0,
//  	    0,
//  	    0,
//  	    0,
//  	    0,
//  	    0,
//  	    0,
//  	    0 });
  	src.put(new byte[] {
  			(byte) 0xaa,
  			2,
  			10,
  			11,
  			12,
  			13,
  			3,
  			(byte) 0xbb });
  	src.flip();
  
  	JBuffer peer = new JBuffer(Type.POINTER);
  	assertTrue(peer.peer(src) != 0);
  	assertEquals(8, peer.size());
  
  	src.order(ByteOrder.BIG_ENDIAN);
  	peer.order(ByteOrder.BIG_ENDIAN);
  	
  	Double.longBitsToDouble(0);
  
  	assertEquals(100.0, (peer.getDouble(0) / src.getDouble(0)) * 100.);
//  	assertEquals(src.getDouble(0), peer.getDouble(0));
  
  	src.order(ByteOrder.LITTLE_ENDIAN);
  	peer.order(ByteOrder.LITTLE_ENDIAN);
  
  	assertEquals(src.getDouble(0), peer.getDouble(0));
  }

}
