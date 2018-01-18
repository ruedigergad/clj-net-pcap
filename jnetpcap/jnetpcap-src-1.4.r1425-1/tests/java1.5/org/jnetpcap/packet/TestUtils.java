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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Image;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Stack;
import java.util.concurrent.Exchanger;
import java.util.concurrent.TimeUnit;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.DefaultListSelectionModel;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.border.BevelBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import junit.framework.TestCase;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapTask;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * Various jUnit support utilities
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestUtils extends TestCase {

	/**
	 * The Class JImagePanel.
	 */
	public static class JImagePanel extends JPanel {

		/** The Constant serialVersionUID. */
		private static final long serialVersionUID = 1L;

		/** The img. */
		private Image img;

		/**
		 * Instantiates a new j image panel.
		 */
		public JImagePanel() {
			super.setSize(new Dimension(100, 100));
		}

		/**
		 * Instantiates a new j image panel.
		 * 
		 * @param img
		 *          the img
		 */
		public JImagePanel(Image img) {
			this.img = img;
		}

		/**
		 * Gets the img.
		 * 
		 * @return the img
		 */
		public final Image getImg() {
			return this.img;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.swing.JComponent#paint(java.awt.Graphics)
		 */
		@Override
		public void paint(Graphics g) {
			super.paint(g);

			if (this.img == null || this.img.getWidth(this) == -1) {
				return;
			}

			Image img = this.img;

			if (img == null) {
				return;
			}

			int w = getWidth();
			int h = getHeight();

			int x = w / 2 - img.getWidth(this) / 2;
			int y = h / 2 - img.getHeight(this) / 2;

			g.drawImage(img, x, y, this);
			g.drawString("(w=" + img.getWidth(this) + ", h=" + img.getHeight(this)
					+ ")", 20, 20);
		}

		/**
		 * Resize to component size.
		 * 
		 * @param img
		 *          the img
		 * @return the image
		 */
		public Image resizeToComponentSize(Image img) {

			int cw = super.getWidth();
			int ch = super.getHeight();
			int iw = img.getWidth(this);
			int ih = img.getHeight(this);
			if (iw == -1 || ih == -1) {
				return img;
			}

			/*
			 * Rescale by width
			 */
			if ((iw > ih) && iw > cw) {
				img = img.getScaledInstance(cw, -1, Image.SCALE_FAST);
			} else if (ih > ch) {
				img = img.getScaledInstance(-1, ch, Image.SCALE_FAST);
			}

			return img;
		}

		/**
		 * Sets the img.
		 * 
		 * @param img
		 *          the new img
		 */
		public final void setImg(Image img) {
			this.img = resizeToComponentSize(img);
		}

	}

	/**
	 * The Class ListOfPanels.
	 */
	public static class ListOfPanels extends JPanel implements
			ListSelectionListener {

		/**
		 * The Class Entry.
		 */
		@SuppressWarnings("unused")
		private static class Entry {

			/** The img. */
			Image img;

			/** The text. */
			String text;

			/**
			 * Instantiates a new entry.
			 * 
			 * @param img
			 *          the img
			 * @param text
			 *          the text
			 */
			public Entry(Image img, String text) {
				this.img = img;
				this.text = text;
			}

			/**
			 * Gets the img.
			 * 
			 * @return the img
			 */
			public final Image getImg() {
				return this.img;
			}

			/**
			 * Gets the text.
			 * 
			 * @return the text
			 */
			public final String getText() {
				return this.text;
			}

			/**
			 * Sets the img.
			 * 
			 * @param img
			 *          the new img
			 */
			public final void setImg(Image img) {
				this.img = img;
			}

			/**
			 * Sets the text.
			 * 
			 * @param text
			 *          the new text
			 */
			public final void setText(String text) {
				this.text = text;
			}

			/*
			 * (non-Javadoc)
			 * 
			 * @see java.lang.Object#toString()
			 */
			@Override
			public String toString() {
				return text;
			}
		}

		/** The Constant serialVersionUID. */
		private static final long serialVersionUID = 7220988908581321871L;

		/** The image panel. */
		private final JImagePanel imagePanel = new JImagePanel();

		/** The jlist. */
		private JList jlist;

		/** The list. */
		private final List<Entry> list = new ArrayList<Entry>(50);

		/** The list model. */
		private DefaultListModel listModel;

		/** The list panel. */
		private final JPanel listPanel = new JPanel();

		/**
		 * Adds the.
		 * 
		 * @param img
		 *          the img
		 * @param text
		 *          the text
		 */
		public void add(Image img, String text) {
			final Entry e = new Entry(img, text);
			list.add(e);

			if (jlist != null) {
				SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						listModel.addElement(e);
						jlist.setSelectedIndex(list.size() - 1);
					}
				});
			}
		}

		/**
		 * Inits the.
		 */
		public void init() {
			super.setPreferredSize(new Dimension(500, 800));
			super.setLayout(new BorderLayout());

			super.add(listPanel, BorderLayout.NORTH);

			super.add(imagePanel, BorderLayout.CENTER);

			listModel = new DefaultListModel();
			jlist = new JList(listModel);
			jlist.addListSelectionListener(this);
			jlist.setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);
			jlist.setLayoutOrientation(JList.VERTICAL_WRAP);

			JScrollPane listScroller = new JScrollPane(jlist);
			listScroller.setPreferredSize(new Dimension(250, 400));
			listScroller.setAlignmentX(LEFT_ALIGNMENT);

			// Create a container so that we can add a title around
			// the scroll pane. Can't add a title directly to the
			// scroll pane because its background would be white.
			// Lay out the label and scroll pane from top to bottom.
			listPanel.setLayout(new BoxLayout(listPanel, BoxLayout.PAGE_AXIS));
			JLabel label = new JLabel("Captured Images");
			label.setLabelFor(jlist);
			listPanel.add(label);
			listPanel.add(Box.createRigidArea(new Dimension(0, 5)));
			listPanel.add(listScroller);
			listPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

			jlist.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
			listPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
			listPanel.setPreferredSize(new Dimension(100, 200));

			if (list.isEmpty() == false) {
				imagePanel.setImg(list.get(list.size() - 1).getImg());
			}
		}

		/**
		 * Checks if is empty.
		 * 
		 * @return true, if is empty
		 */
		public boolean isEmpty() {
			return this.list.isEmpty();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.swing.event.ListSelectionListener#valueChanged(javax.swing.
		 * event.ListSelectionEvent)
		 */
		public void valueChanged(ListSelectionEvent e) {
			// if (e.getValueIsAdjusting()) {
			// return;
			// }

			int first = ((JList) e.getSource()).getSelectedIndex();
			Image img = list.get(first).getImg();

			// Image img = ((JList) e.getSource()).getSelectedIndex();

			imagePanel.setImg(img);
			imagePanel.repaint();
		}

	}

	public static class TestPrintStream extends PrintStream {

		/**
		 * @param out
		 */
		public TestPrintStream(OutputStream out) {
			super(out);
		}

		public int size() {
			return 0;
		}

	}

	/** The Constant AFS. */
	public final static String AFS = "tests/test-afs.pcap";

	/** The Constant DEV_NULL. */
	public final static Appendable DEV_NULL = new Appendable() {

		public Appendable append(char c) throws IOException {
			return this;
		}

		public Appendable append(CharSequence csq) throws IOException {
			return this;
		}

		public Appendable append(CharSequence csq, int start, int end)
				throws IOException {
			return this;
		}

	};

	public final static TestPrintStream DISCARD = new TestPrintStream(
			new OutputStream() {

				/**
				 * @param b
				 * @throws IOException
				 * @see java.io.OutputStream#write(byte[])
				 */
				@Override
				public void write(byte[] b) throws IOException {
				}

				/**
				 * @param b
				 * @param off
				 * @param len
				 * @throws IOException
				 * @see java.io.OutputStream#write(byte[], int, int)
				 */
				@Override
				public void write(byte[] b, int off, int len) throws IOException {
				}

				@Override
				public void write(int b) throws IOException {

				}

			});

	public static TestPrintStream err = new TestPrintStream(System.err);

	private static final Stack<TestPrintStream> errStack =
			new Stack<TestPrintStream>();

	/** The Constant HTTP. */
	public final static String HTTP = "tests/test-http-jpeg.pcap";

	/** The Constant IP6. */
	public final static String IP6 = "tests/test-ipv6.pcap";

	/** The Constant L2TP. */
	public final static String L2TP = "tests/test-l2tp.pcap";

	/** The Constant MYSQL. */
	public final static String MYSQL = "tests/test-mysql.pcap";

	public static TestPrintStream out = new TestPrintStream(System.out);

	private static final Stack<TestPrintStream> outStack =
			new Stack<TestPrintStream>();
	/** The Constant REASEMBLY. */
	public final static String REASEMBLY = "tests/test-ipreassembly.pcap";

	public final static TestPrintStream SAVE = new TestPrintStream(
			new OutputStream() {

				/**
				 * @throws IOException
				 * @see java.io.OutputStream#close()
				 */
				@Override
				public void close() throws IOException {
					flush();
				}

				/**
				 * @throws IOException
				 * @see java.io.OutputStream#flush()
				 */
				@Override
				public void flush() throws IOException {
					if (SAVE_BUFFER.size() != 0) {
						SAVE_BUFFER = new ByteArrayOutputStream();
					}
				}

				/**
				 * @param b
				 * @throws IOException
				 * @see java.io.OutputStream#write(byte[])
				 */
				@Override
				public void write(byte[] b) throws IOException {
					SAVE_BUFFER.write(b);
				}

				/**
				 * @param b
				 * @param off
				 * @param len
				 * @throws IOException
				 * @see java.io.OutputStream#write(byte[], int, int)
				 */
				@Override
				public void write(byte[] b, int off, int len) throws IOException {
					SAVE_BUFFER.write(b, off, len);
				}

				@Override
				public void write(int b) throws IOException {
					SAVE_BUFFER.write(b);
				}

			}) {

		/**
		 * @return
		 * @see org.jnetpcap.packet.TestUtils.TestPrintStream#size()
		 */
		@Override
		public int size() {
			return SAVE_BUFFER.size();
		}

		@Override
		public String toString() {
			return SAVE_BUFFER.toString();
		}
	};

	public static ByteArrayOutputStream SAVE_BUFFER = new ByteArrayOutputStream();

	/** The Constant VLAN. */
	public final static String VLAN = "tests/test-vlan.pcap";

	/** The Constant WIRESHARK_INDEX. */
	public final static int WIRESHARK_INDEX = 1;

	/**
	 * Display in frame.
	 * 
	 * @param c
	 *          the c
	 * @return the j frame
	 */
	public static JFrame displayInFrame(JComponent c) {
		JFrame frame = new JFrame("TestUtils");
		frame.getContentPane().add(c);
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE
				| JFrame.EXIT_ON_CLOSE);

		frame.setSize(new Dimension(400, 800));
		frame.setAlwaysOnTop(true);

		frame.pack();

		frame.setVisible(true);

		return frame;
	}

	/**
	 * Gets the dir file list.
	 * 
	 * @param dir
	 *          the dir
	 * @param endsWith
	 *          the ends with
	 * @return the dir file list
	 */
	public static String[] getDirFileList(File dir, String endsWith) {
		String[] files = dir.list(new FilenameFilter() {

			public boolean accept(File dir, String name) {
				return name.endsWith(".pcap");
			}

		});

		for (int i = 0; i < files.length; i++) {
			files[i] = dir.toString() + "/" + files[i];
		}

		return files;
	}

	/**
	 * Gets the file size aggregate.
	 * 
	 * @param files
	 *          the files
	 * @return the file size aggregate
	 */
	public static long getFileSizeAggregate(String[] files) {
		int size = 0;
		for (String f : files) {
			size += new File(f).length();
		}

		return size;

	}

	/**
	 * Gets the iterable.
	 * 
	 * @param file
	 *          the file
	 * @return the iterable
	 */
	public static Iterable<PcapPacket> getIterable(final String file) {
		return new Iterable<PcapPacket>() {

			public Iterator<PcapPacket> iterator() {
				return getPcapPacketIterator(file, 0, Integer.MAX_VALUE);
			}

		};
	}

	/**
	 * Gets the iterable.
	 * 
	 * @param file
	 *          the file
	 * @param filter
	 *          the filter
	 * @return the iterable
	 */
	public static Iterable<PcapPacket> getIterable(final String file,
			final String filter) {
		return new Iterable<PcapPacket>() {

			public Iterator<PcapPacket> iterator() {
				return getPcapPacketIterator(file, 0, Integer.MAX_VALUE, filter);
			}

		};
	}

	/**
	 * Gets the j packet iterable.
	 * 
	 * @param file
	 *          the file
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the j packet iterable
	 */
	public static Iterable<JPacket> getJPacketIterable(final String file,
			final int start,
			final int end) {

		return new Iterable<JPacket>() {

			public Iterator<JPacket> iterator() {
				final Iterator<PcapPacket> i = getPcapPacketIterator(file, start, end);
				return new Iterator<JPacket>() {

					public boolean hasNext() {
						return i.hasNext();
					}

					public JPacket next() {
						return i.next();
					}

					public void remove() {
						i.remove();
					}

				};
			}

		};
	}

	/**
	 * Gets the pcap packet.
	 * 
	 * @param file
	 *          the file
	 * @param index
	 *          the index
	 * @return the pcap packet
	 */
	public static PcapPacket getPcapPacket(final String file, final int index) {

		/***************************************************************************
		 * First, open offline file
		 **************************************************************************/
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(file, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return null;
		}

		/***************************************************************************
		 * Second, setup a packet we're going to copy the captured contents into.
		 * Allocate 2K native memory block to hold both state and buffer. Notice
		 * that the packet has to be marked "final" in order for the JPacketHandler
		 * to be able to access that variable from within the loop.
		 **************************************************************************/
		final PcapPacket result = new PcapPacket(2 * 1024);

		/***************************************************************************
		 * Third, Enter our loop and count packets until we reach the index of the
		 * packet we are looking for.
		 **************************************************************************/
		try {
			pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {
				int i = 0;

				public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {

					/*********************************************************************
					 * Forth, once we reach our packet transfer the capture data from our
					 * temporary, shared packet, to our preallocated permanent packet. The
					 * method transferStateAndDataTo will do a deep copy of the packet
					 * contents and state to the destination packet. The copy is done
					 * natively with memcpy. The packet content in destination packet is
					 * layout in memory as follows. At the front of the buffer is the
					 * packet_state_t structure followed immediately by the packet data
					 * buffer and its size is adjusted to the exact size of the temporary
					 * buffer. The remainder of the allocated memory block is unused, but
					 * needed to be allocated large enough to hold a decent size packet.
					 * To break out of the Pcap.loop we call Pcap.breakLoop().
					 ********************************************************************/
					if (i++ == index) {
						PcapPacket packet = new PcapPacket(header, buffer);
						packet.scan(JRegistry.mapDLTToId(pcap.datalink()));
						// System.out.println(packet.getState().toDebugString());
						packet.transferStateAndDataTo(result);

						pcap.breakloop();
						return;
					}
				}

			}, pcap);
		} finally {

			/*************************************************************************
			 * Lastly, we close the pcap handle and return our result :)
			 ************************************************************************/
			pcap.close();
		}

		return result;
	}

	/**
	 * Gets the pcap packet iterator.
	 * 
	 * @param file
	 *          the file
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the pcap packet iterator
	 */
	public static Iterator<PcapPacket> getPcapPacketIterator(final String file,
			final int start,
			final int end) {
		return getPcapPacketIterator(file, start, end, null);
	}

	/**
	 * Gets the pcap packet iterator.
	 * 
	 * @param file
	 *          the file
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @param filter
	 *          the filter
	 * @return the pcap packet iterator
	 */
	public static Iterator<PcapPacket> getPcapPacketIterator(final String file,
			final int start,
			final int end,
			String filter) {

		/***************************************************************************
		 * First, open offline file
		 **************************************************************************/
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(file, errbuf);
		assertNotNull(errbuf.toString());

		if (filter != null) {
			PcapBpfProgram prog = new PcapBpfProgram();
			if (pcap.compile(prog, filter, 0, 0xffffff00) != Pcap.OK) {
				System.err.printf("pcap filter %s: %s\n", pcap.getErr(), filter);
				return null;
			}
			pcap.setFilter(prog);
		}

		final Exchanger<PcapPacket> barrier = new Exchanger<PcapPacket>();

		/***************************************************************************
		 * Third, Enter our loop and count packets until we reach the index of the
		 * packet we are looking for.
		 **************************************************************************/

		final PcapTask<Pcap> task = new PcapTask<Pcap>(pcap, end - start, pcap) {

			public void run() {
				try {
					barrier.exchange(null);
				} catch (InterruptedException e1) {
				}

				this.result = pcap.loop(end - start, new PcapPacketHandler<Pcap>() {
					int i = 0;

					public void nextPacket(PcapPacket packet, Pcap pcap) {

						assertNotNull(packet);

						if (i >= start) {
							try {
								barrier.exchange(packet);
							} catch (InterruptedException e) {
								throw new IllegalStateException(e);
							}
						}

						i++;
					}

				}, pcap);

				try {
					barrier.exchange(null, 1000, TimeUnit.MILLISECONDS);
				} catch (Exception e) {
					throw new IllegalStateException(e);
				}
			}

		};

		try {
			task.start();
			barrier.exchange(null); // Synchronize startup
		} catch (InterruptedException e1) {
			throw new IllegalStateException(e1);
		}

		return new Iterator<PcapPacket>() {

			PcapPacket packet;

			public boolean hasNext() {
				try {
					packet = barrier.exchange(null, 1000, TimeUnit.MILLISECONDS);
					return packet != null;

				} catch (Exception e) {
					return false;
				}
			}

			public PcapPacket next() {
				return packet;
			}

			public void remove() {
				throw new UnsupportedOperationException(
						"Invalid operation for readonly offline read");
			}

		};
	}

	/**
	 * Load all packets from files.
	 * 
	 * @param files
	 *          the files
	 * @return the j pcap record buffer
	 */
	public static JPcapRecordBuffer loadAllPacketsFromFiles(String[] files) {

		final StringBuilder errbuf = new StringBuilder();
		final int size = (int) getFileSizeAggregate(files);

		final JPcapRecordBuffer buf = new JPcapRecordBuffer(size);

		for (final String fname : files) {
			Pcap pcap = Pcap.openOffline(fname, errbuf);
			assertNotNull(errbuf.toString(), pcap);

			try {
				pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<String>() {

					public void nextPacket(PcapHeader header, JBuffer buffer, String fname) {
						buf.append(header, buffer);
					}
				},
						fname);
			} catch (RuntimeException e) {
				e.printStackTrace();
				throw e;
			} finally {
				pcap.close();
			}
		}

		buf.close();

		return buf;
	}

	public static JPcapRecordBuffer loadAllTestPackets() {
		String[] files = getDirFileList(new File("tests"), ".pcap");
		JPcapRecordBuffer buffer = loadAllPacketsFromFiles(files);

		return buffer;
	}

	public static JPcapRecordBuffer loadAllPacketsFromFile(String file) {
		JPcapRecordBuffer buffer = loadAllPacketsFromFiles(new String[] { file
		});

		return buffer;
	}

	/**
	 * Open live.
	 * 
	 * @param handler
	 *          the handler
	 */
	public static void openLive(JPacketHandler<Pcap> handler) {
		openLive(Pcap.LOOP_INFINITE, handler);
	}

	/**
	 * Open live.
	 * 
	 * @param count
	 *          the count
	 * @param handler
	 *          the handler
	 */
	public static void openLive(long count, JPacketHandler<Pcap> handler) {
		StringBuilder errbuf = new StringBuilder();
		List<PcapIf> alldevs = new ArrayList<PcapIf>();

		if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
			throw new IllegalStateException(errbuf.toString());
		}

		Pcap pcap =
				Pcap.openLive(alldevs.get(0).getName(),
						Pcap.DEFAULT_SNAPLEN,
						Pcap.DEFAULT_PROMISC,
						Pcap.DEFAULT_TIMEOUT,
						errbuf);
		if (pcap == null) {
			throw new IllegalArgumentException(errbuf.toString());
		}

		pcap.loop((int) count, handler, pcap);
	}

	/**
	 * Open offline.
	 * 
	 * @param fname
	 *          the fname
	 * @return the pcap
	 */
	public static Pcap openOffline(String fname) {
		/***************************************************************************
		 * First, open offline file
		 **************************************************************************/
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(fname, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return null;
		}

		return pcap;
	}

	/**
	 * Open offline.
	 * 
	 * @param file
	 *          the file
	 * @param handler
	 *          the handler
	 */
	public static void openOffline(String file, JPacketHandler<Pcap> handler) {
		openOffline(file, handler, null);
	}

	/**
	 * Open offline.
	 * 
	 * @param file
	 *          the file
	 * @param handler
	 *          the handler
	 * @param filter
	 *          the filter
	 */
	public static void openOffline(String file,
			JPacketHandler<Pcap> handler,
			String filter) {
		StringBuilder errbuf = new StringBuilder();

		Pcap pcap;

		if ((pcap = Pcap.openOffline(file, errbuf)) == null) {
			fail(errbuf.toString());
		}

		if (filter != null) {
			PcapBpfProgram program = new PcapBpfProgram();
			if (pcap.compile(program, filter, 0, 0) != Pcap.OK) {
				System.err.printf("pcap filter err: %s\n", pcap.getErr());
			}

			pcap.setFilter(program);
		}

		pcap.loop(Pcap.LOOP_INFINITE, handler, pcap);

		pcap.close();
	}

	/**
	 * Scan packet.
	 * 
	 * @param packet
	 *          the packet
	 * @return the int
	 */
	public static int scanPacket(JPacket packet) {
		return scanPacket(packet, JProtocol.ETHERNET_ID);
	}

	/**
	 * Scan packet.
	 * 
	 * @param packet
	 *          the packet
	 * @param id
	 *          the id
	 * @return the int
	 */
	public static int scanPacket(JPacket packet, int id) {

		return JScanner.getThreadLocal().scan(packet, id);
	}

	/**
	 * Pcap offline reset.
	 * 
	 * @param pcap
	 *          the pcap
	 */
	protected native void pcapOfflineReset(Pcap pcap);

	/**
	 * @throws Exception
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		outStack.push(out);
		errStack.push(err);
		SAVE.flush();

		super.setUp();
	}

	/**
	 * @throws Exception
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		out = outStack.pop();
		err = errStack.pop();

		super.tearDown();
	}
}
