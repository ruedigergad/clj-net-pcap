/**
 * 
 */
package org.jnetpcap;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.VariousInMemoryPackets;
import org.jnetpcap.protocol.lan.Ethernet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Sly Technologies Inc.
 */
public class TestPcapDumper extends TestCase {

	private PcapDumper dumper;
	private Pcap pcap;
	private File file;
	private final static byte[] data = VariousInMemoryPackets.PACKET_1;
	private final static int fileLength = 24 + 16 + data.length;
	private int useconds;
	private long seconds;
	private int wirelen;

	@Before
	public void setUp() throws IOException {
		file = File.createTempFile("TestPcapDumperJUnitTestCases", "");
		
		pcap = Pcap.openDead(PcapDLT.EN10MB.value, 64 * 1024);
		dumper = pcap.dumpOpen(file.getCanonicalPath());
		
		seconds = System.currentTimeMillis() / 1000;
		useconds = (int) (System.currentTimeMillis() % 1000) * 1000;
		wirelen = data.length;
	}
	
	@After
	public void tearDown() {
		if (dumper != null) {
			dumper.close();
			dumper = null;
		}
		
		if (pcap != null) {
			pcap.close();
			pcap = null;
		}
		
		if (file != null) {
			file.delete();
			file = null;
		}
	}
	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#close()}.
	 */
	@Test
	public void testClose() {
		dumper.close();
		dumper = null;
	}
	
	private void checkFileSize(int size) {
		TestCase.assertEquals(size, (int)file.length());
	}
	
	private void checkFileSize() {
		checkFileSize(fileLength);
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#dump(org.jnetpcap.packet.JMemoryPacket)}.
	 */
	@Test
	public void testDumpJPacket() {
		JMemoryPacket packet = new JMemoryPacket(Ethernet.ID, data);
		
		dumper.dump(packet);
		
		checkFileSize();
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#dump(long, int, int, byte[])}.
	 */
	@Test
	public void testDumpLongIntIntByteArray() {
		dumper.dump(seconds, useconds, wirelen, data);
		
		checkFileSize();
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#dump(long, int, int, byte[], int, int)}.
	 */
	@Test
	public void testDumpLongIntIntByteArrayIntInt() {
		dumper.dump(seconds, useconds, wirelen, data, 10, data.length - 10);
		
		checkFileSize(fileLength - 10);
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#dump(long, int, int, org.jnetpcap.nio.JBuffer)}.
	 */
	@Test
	public void testDumpLongIntIntJBuffer() {
		JBuffer buffer = new JBuffer(data);
		
		dumper.dump(seconds, useconds, wirelen, buffer);
		
		checkFileSize();
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#dump(long, int, int, org.jnetpcap.nio.JBuffer, int, int)}.
	 */
	@Test
	public void testDumpLongIntIntJBufferIntInt() {
		JBuffer buffer = new JBuffer(data);
		
		dumper.dump(seconds, useconds, wirelen, buffer, 10, data.length - 10);
		
		checkFileSize(fileLength - 10);
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#dump(org.jnetpcap.PcapHeader, java.nio.ByteBuffer)}.
	 */
	@Test
	public void testDumpJCaptureHeaderByteBuffer() {
		PcapHeader header = new PcapHeader(data.length, data.length);
		ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
		buffer.put(data);
		buffer.flip();

		dumper.dump(header, buffer);
		
		checkFileSize();
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#dump(org.jnetpcap.PcapHeader, org.jnetpcap.nio.JBuffer)}.
	 */
	@Test
	public void testDumpJCaptureHeaderJBuffer() {
		JBuffer buffer = new JBuffer(data);
		PcapHeader header = new PcapHeader(data.length, data.length);
		
		dumper.dump(header, buffer);
		
		checkFileSize();
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#flush()}.
	 */
	@Test
	public void testFlush() {
		JBuffer buffer = new JBuffer(data);
		PcapHeader header = new PcapHeader(data.length, data.length);
		
		dumper.dump(header, buffer);
		
		dumper.flush();
		
		checkFileSize();
	}

	/**
	 * Test method for {@link org.jnetpcap.PcapDumper#ftell()}.
	 */
	@Test
	public void testFtell() {
		JBuffer buffer = new JBuffer(data);
		PcapHeader header = new PcapHeader(data.length, data.length);
		
		dumper.dump(header, buffer);
		
		dumper.flush();
		
		checkFileSize();
		
		TestCase.assertEquals(fileLength, (int)dumper.ftell());
	}

}
