/**
 * 
 */
package org.jnetpcap.packet;

import junit.framework.TestCase;

import org.jnetpcap.protocol.JProtocol;
import org.junit.Test;

/**
 * 
 * @author Sly Technologies Inc.
 */
public class TestJProtocol {

	// @Test
	public void idToMask() {

		for (int i = 0; i < 1024; i++) {
			long mapIndex = i >> 5;
			long expected = (long) ((mapIndex << 32) | (1L << (i & 0x1F)));
			long actual = JProtocol.idToMask(i);
			System.out.printf("#%4d = 0x%016X mapIndex=%d%n", i, actual,
					mapIndex);

			TestCase.assertEquals(String
					.format("expected: 0x%016X but was 0x%016X ---- ",
							expected, actual), expected, actual);

		}

		try {
			JProtocol.idToMask(1024);
			TestCase.fail("value range is between 0 and 1024");
		} catch (IllegalArgumentException e) {
			// Good
		}
		try {
			JProtocol.idToMask(-1);
			TestCase.fail("value range is between 0 and "
					+ JRegistry.MAX_ID_COUNT);
		} catch (IllegalArgumentException e) {
			// Good
		}

		try {
			JProtocol.idToMask(100000000);
			TestCase.fail("value range is between 0 and "
					+ JRegistry.MAX_ID_COUNT);
		} catch (IllegalArgumentException e) {
			// Good
		}
	}

	@Test
	public void testMaskToId() {
		for (int i = 0; i < 1024; i++) {
			long mask = JProtocol.idToMask(i);
			int id = JProtocol.maskToId(mask);

			// System.out.printf("#%2d - id=%2d mask=0x%016X%n", i, id, mask);
			TestCase.assertEquals(i & 0x1F, id);
		}

	}

	@Test
	public void testMaskToMapIndex() {
		for (int i = 0; i < 1024; i++) {
			long mask = JProtocol.idToMask(i);
			int mapIndex = JProtocol.maskToGroup(mask);

			// System.out.printf("#%2d - mapIndex=%2d mask=0x%016X%n", i,
			// mapIndex, mask);
			TestCase.assertEquals(i >> 5, mapIndex);
		}

	}

}
