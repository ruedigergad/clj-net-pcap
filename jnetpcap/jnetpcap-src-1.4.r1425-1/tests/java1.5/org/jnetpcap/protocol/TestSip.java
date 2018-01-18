/**
 * 
 */
package org.jnetpcap.protocol;

import java.io.File;
import java.io.PrintStream;

import junit.framework.TestCase;

import org.jnetpcap.packet.AbstractMessageHeader.MessageType;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.SLL;
import org.jnetpcap.protocol.voip.Sip;
import org.jnetpcap.protocol.voip.Sip.Method;
import org.junit.Test;

/**
 * 
 * @author Sly Technologies Inc.
 */
@SuppressWarnings("unused")
public class TestSip extends TestCase {

//	private final static PrintStream out = System.out;
	 private final static PrintStream out = TestUtils.DISCARD;

	@Test
	public void testSipINFO() {

		/**
		 * <pre>
		 * JPacket.State#000   : [         Protocol(ID/Flag) | Start | Prefix | Header | Gap | Payload | Postfix ]
		 * JPacket.State#000[0]: [              SLL(20/0800) |     0 |      0 |     16 |   0 |    1207 |       0 ]
		 * JPacket.State#000[1]: [              IP4( 2/0800) |    16 |      0 |     20 |   0 |    1187 |       0 ]
		 * JPacket.State#000[2]: [              UDP( 5/0800) |    36 |      0 |      8 |   0 |    1179 |       0 ]
		 * JPacket.State#000[3]: [              SIP(17/0800) |    44 |      0 |    410 |   0 |     769 |       0 ]
		 * JPacket.State#000[4]: [              SDP(18/0800) |   454 |      0 |    769 |   0 |       0 |       0 ]
		 * Frame:
		 * Frame:                                  number = 0
		 * Frame:                               timestamp = 2012-06-23 02:38:41.89
		 * Frame:                             wire length = 1223 bytes
		 * Frame:                         captured length = 1223 bytes
		 * Frame:
		 * SLL:  ******* SLL - "Linux Cooked Capture" - offset=0 (0x0) length=16 protocol suite=LAN
		 * SLL: 
		 * SLL:                               packetType = 4
		 * SLL:                                   haType = 1
		 * SLL:                                 haLength = 6
		 * SLL:                                  address = 00:0c:29:92:d6:9a
		 * SLL:                                     type = 0x800 (2048)
		 * SLL: 
		 * Ip:  ******* Ip4 - "ip version 4" - offset=16 (0x10) length=20 protocol suite=NETWORK
		 * Ip: 
		 * Ip:                                  version = 4
		 * Ip:                                     hlen = 5 [5 * 4 = 20 bytes, No Ip Options]
		 * Ip:                                 diffserv = 0x0 (0)
		 * Ip:                    0000 00.. = [0] code point: not set
		 * Ip:                    .... ..0. = [0] ECN bit: not set
		 * Ip:                    .... ...0 = [0] ECE bit: not set
		 * Ip:                                   length = 1207
		 * Ip:                                       id = 0x0 (0)
		 * Ip:                                    flags = 0x2 (2)
		 * Ip:                    0.. = [0] reserved
		 * Ip:                    .1. = [1] DF: do not fragment: set
		 * Ip:                    ..0 = [0] MF: more fragments: not set
		 * Ip:                                   offset = 0
		 * Ip:                                      ttl = 64 [time to live]
		 * Ip:                                     type = 17 [next: User Datagram]
		 * Ip:                                 checksum = 0x5347 (21319) [correct]
		 * Ip:                                   source = 10.30.103.158
		 * Ip:                              destination = 10.30.103.21
		 * Ip: 
		 * Udp:  ******* Udp offset=36 (0x24) length=8 
		 * Udp: 
		 * Udp:                                   source = 5060
		 * Udp:                              destination = 5060
		 * Udp:                                   length = 1187
		 * Udp:                                 checksum = 0xE7A3 (59299) [correct]
		 * Udp: 
		 * Sip:  ******* Sip offset=44 (0x2C) length=410 
		 * Sip: 
		 * Sip:                           CONTENT-LENGTH = 769
		 * Sip:                                       TO = <sip:msml@10.30.103.21:5060>;tag=10.30.103.215060+1+fc350011+ce8dae3e
		 * Sip:                                  CONTACT = <sip:10.30.103.158:5060;transport=UDP>
		 * Sip:                                     CSEQ = 2 INFO
		 * Sip:                                      VIA = SIP/2.0/UDP 10.30.103.158:5060;branch=z9hG4bKnJS4G5DbxQyp2JrsZ4FJO1
		 * Sip:                                  CALL-ID = dDAwWT9TjD
		 * Sip:                             CONTENT-TYPE = application/msml+xml
		 * Sip:                                     FROM = "vflipslee2"<sip:vflipslee2@10.30.0.155>;tag=1213583013402945739861.0
		 * Sip: 
		 * Sdp:  ******* Sdp offset=454 (0x1C6) length=769 
		 * Sdp: 
		 * Sdp
		 * 
		 * </pre>
		 */
		final byte[] data = FormatUtils.toByteArray(""
				+ "000400010006000c2992d69a00000800"
				+ "450004b700004000401153470a1e679e"
				+ "0a1e671513c413c404a3e7a3494e464f"
				+ "207369703a6d736d6c4031302e33302e"
				+ "3130332e32313a35303630205349502f"
				+ "322e300d0a436f6e74656e742d4c656e"
				+ "6774683a203736390d0a546f3a203c73"
				+ "69703a6d736d6c4031302e33302e3130"
				+ "332e32313a353036303e3b7461673d31"
				+ "302e33302e3130332e3231353036302b"
				+ "312b66633335303031312b6365386461"
				+ "6533650d0a436f6e746163743a203c73"
				+ "69703a31302e33302e3130332e313538"
				+ "3a353036303b7472616e73706f72743d"
				+ "5544503e0d0a435365713a203220494e"
				+ "464f0d0a5669613a205349502f322e30"
				+ "2f5544502031302e33302e3130332e31"
				+ "35383a353036303b6272616e63683d7a"
				+ "39684734624b6e4a5334473544627851"
				+ "7970324a72735a34464a4f310d0a4361"
				+ "6c6c2d49443a2064444177575439546a"
				+ "440d0a436f6e74656e742d547970653a"
				+ "206170706c69636174696f6e2f6d736d"
				+ "6c2b786d6c0d0a46726f6d3a20227666"
				+ "6c6970736c656532223c7369703a7666"
				+ "6c6970736c6565324031302e33302e30"
				+ "2e3135353e3b7461673d313231333538"
				+ "33303133343032393435373339383631"
				+ "2e300d0a0d0a3c3f786d6c2076657273"
				+ "696f6e3d27312e302720656e636f6469"
				+ "6e673d2755532d4153434949273f3e3c"
				+ "6d736d6c2076657273696f6e3d27312e"
				+ "31273e3c6469616c6f67737461727420"
				+ "7461726765743d27636f6e6e3a31302e"
				+ "33302e3130332e3231353036302b312b"
				+ "66633335303031312b63653864616533"
				+ "652720747970653d276170706c696361"
				+ "74696f6e2f6d6f6d6c2b786d6c27206e"
				+ "616d653d27656e74657270696e416e6e"
				+ "6327203e3c706c6179206376643a6261"
				+ "7267653d277472756527206376643a63"
				+ "6c65617264623d2766616c736527203e"
				+ "3c617564696f207572693d2766696c65"
				+ "3a2f2f6d6e742f31302e33302e313032"
				+ "2e3131362f62742f4d4d322f656e672f"
				+ "70696e5f70726f6d70742e7761762720"
				+ "2f3e3c706c6179657869743e3c657869"
				+ "74206e616d656c6973743d27706c6179"
				+ "2e656e64272f3e3c2f706c6179657869"
				+ "743e3c2f706c61793e3c2f6469616c6f"
				+ "6773746172743e3c6469616c6f677374"
				+ "617274207461726765743d27636f6e6e"
				+ "3a31302e33302e3130332e3231353036"
				+ "302b312b66633335303031312b636538"
				+ "64616533652720747970653d27617070"
				+ "6c69636174696f6e2f6d6f6d6c2b786d"
				+ "6c27206e616d653d27656e7465727069"
				+ "6e44746d6627203e3c64746d66206664"
				+ "743d2732307327206964743d27313073"
				+ "27206564743d2735732720636c656172"
				+ "64623d2766616c736527203e3c706174"
				+ "7465726e206469676974733d276d696e"
				+ "3d313b6d61783d32383b72746b3d2327"
				+ "20666f726d61743d276d6f6d6c2b6469"
				+ "67697473273e3c65786974206e616d65"
				+ "6c6973743d2764746d662e6469676974"
				+ "732064746d662e656e64272f3e3c2f70"
				+ "61747465726e3e3c6e6f696e7075743e"
				+ "3c65786974206e616d656c6973743d27"
				+ "64746d662e6469676974732064746d66"
				+ "2e656e64272f3e3c2f6e6f696e707574"
				+ "3e3c6e6f6d617463683e3c6578697420"
				+ "6e616d656c6973743d2764746d662e64"
				+ "69676974732064746d662e656e64272f"
				+ "3e3c2f6e6f6d617463683e3c2f64746d"
				+ "663e3c2f6469616c6f6773746172743" + "e3c2f6d736d6c3e" + "");

		final JPacket packet = new JMemoryPacket(SLL.ID, data);
		out.println(packet.getState().toDebugString());
		out.println(packet);

		TestCase.assertTrue(packet.hasHeader(sip));
		TestCase.assertEquals(MessageType.REQUEST, sip.getMessageType());
		TestCase.assertTrue(sip.hasField(Sip.Request.RequestMethod));
		TestCase.assertEquals("INFO", sip.fieldValue(Sip.Request.RequestMethod));
		TestCase.assertEquals(Method.INFO, sip.getMethod());
		TestCase.assertTrue(sip.hasMethod(Method.INFO));
	}

	private final Sip sip = new Sip();

	@Test
	public void testSipOPTIONS() {

		/**
		 * <pre>
		 * JPacket.State#001   : [         Protocol(ID/Flag) | Start | Prefix | Header | Gap | Payload | Postfix ]
		 * JPacket.State#001[0]: [              SLL(20/0800) |     0 |      0 |     16 |   0 |     698 |       0 ]
		 * JPacket.State#001[1]: [              IP4( 2/0800) |    16 |      0 |     20 |   0 |     678 |       0 ]
		 * JPacket.State#001[2]: [              UDP( 5/0800) |    36 |      0 |      8 |   0 |     670 |       0 ]
		 * JPacket.State#001[3]: [              SIP(17/0800) |    44 |      0 |    670 |   0 |       0 |       0 ]
		 * 
		 * 
		 * Frame:
		 * Frame:                                  number = 1
		 * Frame:                               timestamp = 2012-06-23 02:55:11.145
		 * Frame:                             wire length = 714 bytes
		 * Frame:                         captured length = 714 bytes
		 * Frame:
		 * SLL:  ******* SLL - "Linux Cooked Capture" - offset=0 (0x0) length=16 protocol suite=LAN
		 * SLL: 
		 * SLL:                               packetType = 0
		 * SLL:                                   haType = 1
		 * SLL:                                 haLength = 6
		 * SLL:                                  address = 00:0c:29:03:74:83
		 * SLL:                                     type = 0x800 (2048)
		 * SLL: 
		 * Ip:  ******* Ip4 - "ip version 4" - offset=16 (0x10) length=20 protocol suite=NETWORK
		 * Ip: 
		 * Ip:                                  version = 4
		 * Ip:                                     hlen = 5 [5 * 4 = 20 bytes, No Ip Options]
		 * Ip:                                 diffserv = 0x0 (0)
		 * Ip:                    0000 00.. = [0] code point: not set
		 * Ip:                    .... ..0. = [0] ECN bit: not set
		 * Ip:                    .... ...0 = [0] ECE bit: not set
		 * Ip:                                   length = 698
		 * Ip:                                       id = 0x8340 (33600)
		 * Ip:                                    flags = 0x0 (0)
		 * Ip:                    0.. = [0] reserved
		 * Ip:                    .0. = [0] DF: do not fragment: not set
		 * Ip:                    ..0 = [0] MF: more fragments: not set
		 * Ip:                                   offset = 0
		 * Ip:                                      ttl = 64 [time to live]
		 * Ip:                                     type = 17 [next: User Datagram]
		 * Ip:                                 checksum = 0x118D (4493) [correct]
		 * Ip:                                   source = 10.30.103.140
		 * Ip:                              destination = 10.30.103.158
		 * Ip: 
		 * Udp:  ******* Udp offset=36 (0x24) length=8 
		 * Udp: 
		 * Udp:                                   source = 5090
		 * Udp:                              destination = 5060
		 * Udp:                                   length = 678
		 * Udp:                                 checksum = 0x43E6 (17382) [correct]
		 * Udp: 
		 * Sip:  ******* Sip offset=44 (0x2C) length=670 
		 * Sip: 
		 * Sip:                                      VIA = SIP/2.0/UDP 10.30.103.140:5090;rport;branch=z9hG4bKjS639D3NZ6SSH
		 * Sip:                             MAX-FORWARDS = 70
		 * Sip:                                     FROM = <sip:none@10.30.103.158:5060;transport=udp>;tag=K9XZXy30XgBUN
		 * Sip:                                       TO = <sip:none@10.30.103.158:5060;transport=udp>
		 * Sip:                                  CALL-ID = 64b74290-365d-1230-6191-000c2903746f
		 * Sip:                                     CSEQ = 24035150 OPTIONS
		 * Sip:                                  CONTACT = <sip:gw+flip@10.30.103.140:5090;transport=udp;gw=flip>
		 * Sip:                               USER-AGENT = FreeSWITCH-mod_sofia/1.0.head-git-fb6e979 2011-08-26 04-48-33 +0000
		 * Sip:                                    ALLOW = INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, UPDATE, INFO, REGISTER, REFER, NOTIFY
		 * Sip:                                SUPPORTED = timer, precondition, path, replaces
		 * Sip:                           CONTENT-LENGTH = 0
		 * Sip:
		 * 
		 * </pre>
		 */
		final byte[] data = FormatUtils
				.toByteArray(""
						+ "000000010006000c2903748300000800450002ba834000004011118d0a1e678c"
						+ "0a1e679e13e213c402a643e64f5054494f4e53207369703a31302e33302e3130"
						+ "332e3135383a353036303b7472616e73706f72743d756470205349502f322e30"
						+ "0d0a5669613a205349502f322e302f5544502031302e33302e3130332e313430"
						+ "3a353039303b72706f72743b6272616e63683d7a39684734624b6a5336333944"
						+ "334e5a365353480d0a4d61782d466f7277617264733a2037300d0a46726f6d3a"
						+ "203c7369703a6e6f6e654031302e33302e3130332e3135383a353036303b7472"
						+ "616e73706f72743d7564703e3b7461673d4b39585a58793330586742554e0d0a"
						+ "546f3a203c7369703a6e6f6e654031302e33302e3130332e3135383a35303630"
						+ "3b7472616e73706f72743d7564703e0d0a43616c6c2d49443a20363462373432"
						+ "39302d333635642d313233302d363139312d3030306332393033373436660d0a"
						+ "435365713a203234303335313530204f5054494f4e530d0a436f6e746163743a"
						+ "203c7369703a67772b666c69704031302e33302e3130332e3134303a35303930"
						+ "3b7472616e73706f72743d7564703b67773d666c69703e0d0a557365722d4167"
						+ "656e743a20467265655357495443482d6d6f645f736f6669612f312e302e6865"
						+ "61642d6769742d6662366539373920323031312d30382d32362030342d34382d"
						+ "3333202b303030300d0a416c6c6f773a20494e564954452c2041434b2c204259"
						+ "452c2043414e43454c2c204f5054494f4e532c204d4553534147452c20555044"
						+ "4154452c20494e464f2c2052454749535445522c2052454645522c204e4f5449"
						+ "46590d0a537570706f727465643a2074696d65722c20707265636f6e64697469"
						+ "6f6e2c20706174682c207265706c616365730d0a416c6c6f772d4576656e7473"
						+ "3a2074616c6b2c20686f6c642c2072656665720d0a436f6e74656e742d4c656e"
						+ "6774683a20300d0a0d0a");
		final JPacket packet = new JMemoryPacket(SLL.ID, data);
		out.println(packet.getState().toDebugString());
		out.println(packet);

		TestCase.assertTrue(packet.hasHeader(sip));
		TestCase.assertEquals(MessageType.REQUEST, sip.getMessageType());
		TestCase.assertTrue(sip.hasField(Sip.Request.RequestMethod));
		TestCase.assertEquals("OPTIONS",
				sip.fieldValue(Sip.Request.RequestMethod));
		TestCase.assertEquals(Method.OPTIONS, sip.getMethod());
		TestCase.assertTrue(sip.hasMethod(Method.OPTIONS));

	}

	public void testSipINVITE() {

		/**
		 * <pre>
		 * JPacket.State#002   : [         Protocol(ID/Flag) | Start | Prefix | Header | Gap | Payload | Postfix ]
		 * JPacket.State#002[0]: [              SLL(20/0800) |     0 |      0 |     16 |   0 |    1164 |       0 ]
		 * JPacket.State#002[1]: [              IP4( 2/0800) |    16 |      0 |     20 |   0 |    1144 |       0 ]
		 * JPacket.State#002[2]: [              UDP( 5/0800) |    36 |      0 |      8 |   0 |    1136 |       0 ]
		 * JPacket.State#002[3]: [              SIP(17/0800) |    44 |      0 |   1136 |   0 |       0 |       0 ]
		 * 
		 * 
		 * Frame:
		 * Frame:                                  number = 2
		 * Frame:                               timestamp = 2012-06-23 04:30:45.383
		 * Frame:                             wire length = 1180 bytes
		 * Frame:                         captured length = 1180 bytes
		 * Frame:
		 * SLL:  ******* SLL - "Linux Cooked Capture" - offset=0 (0x0) length=16 protocol suite=LAN
		 * SLL: 
		 * SLL:                               packetType = 0
		 * SLL:                                   haType = 1
		 * SLL:                                 haLength = 6
		 * SLL:                                  address = 00:0c:29:03:74:83
		 * SLL:                                     type = 0x800 (2048)
		 * SLL: 
		 * Ip:  ******* Ip4 - "ip version 4" - offset=16 (0x10) length=20 protocol suite=NETWORK
		 * Ip: 
		 * Ip:                                  version = 4
		 * Ip:                                     hlen = 5 [5 * 4 = 20 bytes, No Ip Options]
		 * Ip:                                 diffserv = 0x0 (0)
		 * Ip:                    0000 00.. = [0] code point: not set
		 * Ip:                    .... ..0. = [0] ECN bit: not set
		 * Ip:                    .... ...0 = [0] ECE bit: not set
		 * Ip:                                   length = 1164
		 * Ip:                                       id = 0x8341 (33601)
		 * Ip:                                    flags = 0x0 (0)
		 * Ip:                    0.. = [0] reserved
		 * Ip:                    .0. = [0] DF: do not fragment: not set
		 * Ip:                    ..0 = [0] MF: more fragments: not set
		 * Ip:                                   offset = 0
		 * Ip:                                      ttl = 64 [time to live]
		 * Ip:                                     type = 17 [next: User Datagram]
		 * Ip:                                 checksum = 0xFBA (4026) [correct]
		 * Ip:                                   source = 10.30.103.140
		 * Ip:                              destination = 10.30.103.158
		 * Ip: 
		 * Udp:  ******* Udp offset=36 (0x24) length=8 
		 * Udp: 
		 * Udp:                                   source = 5090
		 * Udp:                              destination = 5060
		 * Udp:                                   length = 1144
		 * Udp:                                 checksum = 0x94C (2380) [correct]
		 * Udp: 
		 * Sip:  ******* Sip offset=44 (0x2C) length=1136 
		 * Sip: 
		 * Sip:                            RequestMethod = INVITE
		 * Sip:                               RequestUrl = sip:12345678@10.30.103.158:5060
		 * Sip:                           RequestVersion = SIP/2.0
		 * Sip:                                      VIA = SIP/2.0/UDP 10.30.103.140:5090;rport;branch=z9hG4bKK2ZvB9KSvFgcD
		 * Sip:                             MAX-FORWARDS = 68
		 * Sip:                                     FROM = "eeeeeeugggg" <sip:6120@10.30.103.140>;tag=mjQrZSm4tS1DH
		 * Sip:                                       TO = <sip:12345678@10.30.103.158:5060>
		 * Sip:                                  CALL-ID = 66a26179-365d-1230-6191-000c2903746f
		 * Sip:                                     CSEQ = 29811222 INVITE
		 * Sip:                                  CONTACT = <sip:gw+flip@10.30.103.140:5090;transport=udp;gw=flip>
		 * Sip:                               USER-AGENT = FreeSWITCH-mod_sofia/1.0.head-git-fb6e979 2011-08-26 04-48-33 +0000
		 * Sip:                                    ALLOW = INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, UPDATE, INFO, REGISTER, REFER, NOTIFY
		 * Sip:                                SUPPORTED = timer, precondition, path, replaces
		 * Sip:                             CONTENT-TYPE = application/sdp
		 * Sip:                      CONTENT-DISPOSITION = session
		 * Sip:                           CONTENT-LENGTH = 303
		 * Sip:
		 * 
		 * </pre>
		 */
		final byte[] data = FormatUtils
				.toByteArray(""
						+ "000000010006000c29037483000008004500048c8341000040110fba0a1e678c"
						+ "0a1e679e13e213c40478094c494e56495445207369703a313233343536373840"
						+ "31302e33302e3130332e3135383a35303630205349502f322e300d0a5669613a20"
						+ "5349502f322e302f5544502031302e33302e3130332e3134303a353039303b7270"
						+ "6f72743b6272616e63683d7a39684734624b4b325a7642394b5376466763440d0a"
						+ "4d61782d466f7277617264733a2036380d0a46726f6d3a20226565656565666666"
						+ "676722203c7369703a363132304031302e33302e3130332e3134303e3b7461673d"
						+ "6d6a51725a536d3474533144480d0a546f3a203c7369703a313233343536373840"
						+ "31302e33302e3130332e3135383a353036303e0d0a43616c6c2d49443a20363661"
						+ "32363137392d333635642d313233302d363139312d303030633239303337343666"
						+ "0d0a435365713a20323938313132323220494e564954450d0a436f6e746163743a"
						+ "203c7369703a67772b666c69704031302e33302e3130332e3134303a353039303b"
						+ "7472616e73706f72743d7564703b67773d666c69703e0d0a557365722d4167656e"
						+ "743a20467265655357495443482d6d6f645f736f6669612f312e302e686561642d"
						+ "6769742d6662366539373920323031312d30382d32362030342d34382d3333202b"
						+ "303030300d0a416c6c6f773a20494e564954452c2041434b2c204259452c204341"
						+ "4e43454c2c204f5054494f4e532c204d4553534147452c205550444154452c2049"
						+ "4e464f2c2052454749535445522c2052454645522c204e4f544946590d0a537570"
						+ "706f727465643a2074696d65722c20707265636f6e646974696f6e2c2070617468"
						+ "2c207265706c616365730d0a416c6c6f772d4576656e74733a2074616c6b2c2068"
						+ "6f6c642c2072656665720d0a436f6e74656e742d547970653a206170706c696361"
						+ "74696f6e2f7364700d0a436f6e74656e742d446973706f736974696f6e3a207365"
						+ "7373696f6e0d0a436f6e74656e742d4c656e6774683a203330330d0a582d46532d"
						+ "537570706f72743a207570646174655f646973706c61790d0a52656d6f74652d50"
						+ "617274792d49443a20226565656565756767676722203c7369703a363132304031"
						+ "302e33302e3130332e3134303e3b70617274793d63616c6c696e673b7363726565"
						+ "6e3d7965733b707269766163793d6f66660d0a0d0a763d300d0a6f3d4672656553"
						+ "57495443482031333430323737313031203133343032373731303220494e204950"
						+ "342031302e33302e3130342e3134300d0a733d467265655357495443480d0a633d"
						+ "494e204950342031302e33302e3130342e3134300d0a743d3020300d0a6d3d6175"
						+ "64696f203137343732205254502f4156502030203130312031330d0a613d727470"
						+ "6d61703a3130312074656c6570686f6e652d6576656e742f383030300d0a613d66"
						+ "6d74703a31303120302d31360d0a613d7074696d653a33300d0a6d3d617564696f"
						+ "203137343732205254502f415650203020382033203130312031330d0a613d7274"
						+ "706d61703a3130312074656c6570686f6e652d6576656e742f383030300d0a613d"
						+ "666d74703a31303120302d31360d0a613d7074696d653a32300d0a");

		final JPacket packet = new JMemoryPacket(SLL.ID, data);
		out.println(packet.getState().toDebugString());
		out.println(packet);

		TestCase.assertTrue(packet.hasHeader(sip));
		TestCase.assertEquals(MessageType.REQUEST, sip.getMessageType());
		TestCase.assertTrue(sip.hasField(Sip.Request.RequestMethod));
		TestCase.assertEquals("INVITE",
				sip.fieldValue(Sip.Request.RequestMethod));
		TestCase.assertEquals(Method.INVITE, sip.getMethod());
		TestCase.assertTrue(sip.hasMethod(Method.INVITE));
	}

	@Test
	public void testSipACK() {

		/**
		 * <pre>
		 * JPacket.State#003   : [         Protocol(ID/Flag) | Start | Prefix | Header | Gap | Payload | Postfix ]
		 * JPacket.State#003[0]: [              SLL(20/0800) |     0 |      0 |     16 |   0 |     460 |       0 ]
		 * JPacket.State#003[1]: [              IP4( 2/0800) |    16 |      0 |     20 |   0 |     440 |       0 ]
		 * JPacket.State#003[2]: [              UDP( 5/0800) |    36 |      0 |      8 |   0 |     432 |       0 ]
		 * JPacket.State#003[3]: [              SIP(17/0800) |    44 |      0 |    432 |   0 |       0 |       0 ]
		 * 
		 * 
		 * Frame:
		 * Frame:                                  number = 3
		 * Frame:                               timestamp = 2012-06-23 04:43:17.262
		 * Frame:                             wire length = 476 bytes
		 * Frame:                         captured length = 476 bytes
		 * Frame:
		 * SLL:  ******* SLL - "Linux Cooked Capture" - offset=0 (0x0) length=16 protocol suite=LAN
		 * SLL: 
		 * SLL:                               packetType = 0
		 * SLL:                                   haType = 1
		 * SLL:                                 haLength = 6
		 * SLL:                                  address = 00:0c:29:03:74:83
		 * SLL:                                     type = 0x800 (2048)
		 * SLL: 
		 * Ip:  ******* Ip4 - "ip version 4" - offset=16 (0x10) length=20 protocol suite=NETWORK
		 * Ip: 
		 * Ip:                                  version = 4
		 * Ip:                                     hlen = 5 [5 * 4 = 20 bytes, No Ip Options]
		 * Ip:                                 diffserv = 0x0 (0)
		 * Ip:                    0000 00.. = [0] code point: not set
		 * Ip:                    .... ..0. = [0] ECN bit: not set
		 * Ip:                    .... ...0 = [0] ECE bit: not set
		 * Ip:                                   length = 460
		 * Ip:                                       id = 0x8342 (33602)
		 * Ip:                                    flags = 0x0 (0)
		 * Ip:                    0.. = [0] reserved
		 * Ip:                    .0. = [0] DF: do not fragment: not set
		 * Ip:                    ..0 = [0] MF: more fragments: not set
		 * Ip:                                   offset = 0
		 * Ip:                                      ttl = 64 [time to live]
		 * Ip:                                     type = 17 [next: User Datagram]
		 * Ip:                                 checksum = 0x1279 (4729) [correct]
		 * Ip:                                   source = 10.30.103.140
		 * Ip:                              destination = 10.30.103.158
		 * Ip: 
		 * Udp:  ******* Udp offset=36 (0x24) length=8 
		 * Udp: 
		 * Udp:                                   source = 5090
		 * Udp:                              destination = 5060
		 * Udp:                                   length = 440
		 * Udp:                                 checksum = 0x45F3 (17907) [correct]
		 * Udp: 
		 * Sip:  ******* Sip offset=44 (0x2C) length=432 
		 * Sip: 
		 * Sip:                            RequestMethod = ACK
		 * Sip:                               RequestUrl = sip:12345678@10.30.103.158:5060;transport=UDP
		 * Sip:                           RequestVersion = SIP/2.0
		 * Sip:                                      VIA = SIP/2.0/UDP 10.30.103.140:5090;rport;branch=z9hG4bKmBSND44vSr6yr
		 * Sip:                             MAX-FORWARDS = 70
		 * Sip:                                     FROM = "eeeeeeugggg" <sip:6120@10.30.103.140>;tag=mjQrZSm4tS1DH
		 * Sip:                                       TO = <sip:12345678@10.30.103.158:5060>;tag=1213583113402945740001.0
		 * Sip:                                  CALL-ID = 66a26179-365d-1230-6191-000c2903746f
		 * Sip:                                     CSEQ = 29811222 ACK
		 * Sip:                                  CONTACT = <sip:gw+flip@10.30.103.140:5090;transport=udp;gw=flip>
		 * Sip:                           CONTENT-LENGTH = 0
		 * Sip:
		 * 
		 * </pre>
		 */
		final byte[] data = FormatUtils
				.toByteArray(""
						+ "000000010006000c2903748300000800450001cc83420000401112790a1e678c0a"
						+ "1e679e13e213c401b845f341434b207369703a31323334353637384031302e3330"
						+ "2e3130332e3135383a353036303b7472616e73706f72743d554450205349502f32"
						+ "2e300d0a5669613a205349502f322e302f5544502031302e33302e3130332e313430"
						+ "3a353039303b72706f72743b6272616e63683d7a39684734624b6d42534e44343476"
						+ "53723679720d0a4d61782d466f7277617264733a2037300d0a46726f6d3a20226565"
						+ "732066666667676722203c7369703a363132304031302e33302e3130332e3134303e"
						+ "3b7461673d6d6a51725a536d3474533144480d0a546f3a203c7369703a3132333435"
						+ "3637384031302e33302e3130332e3135383a353036303e3b7461673d313231333538"
						+ "333131333430323934353734303030312e300d0a43616c6c2d49443a203636613236"
						+ "3137392d333635642d313233302d363139312d3030306332393033373436660d0a43"
						+ "5365713a2032393831313232322041434b0d0a436f6e746163743a203c7369703a67"
						+ "772b666c69704031302e33302e3130332e3134303a353039303b7472616e73706f72"
						+ "743d7564703b67773d666c69703e0d0a436f6e74656e742d4c656e6774683a20300d"
						+ "0a0d0a");

		final JPacket packet = new JMemoryPacket(SLL.ID, data);
		out.println(packet.getState().toDebugString());
		out.println(packet);

		TestCase.assertTrue(packet.hasHeader(sip));
		TestCase.assertEquals(MessageType.REQUEST, sip.getMessageType());
		TestCase.assertTrue(sip.hasField(Sip.Request.RequestMethod));
		TestCase.assertEquals("ACK", sip.fieldValue(Sip.Request.RequestMethod));
		TestCase.assertEquals(Method.ACK, sip.getMethod());
		TestCase.assertTrue(sip.hasMethod(Method.ACK));
	}

	public void testSipBYE() {

		/**
		 * <pre>
		 * JPacket.State#004   : [         Protocol(ID/Flag) | Start | Prefix | Header | Gap | Payload | Postfix ]
		 * JPacket.State#004[0]: [              SLL(20/0800) |     0 |      0 |     16 |   0 |     726 |       0 ]
		 * JPacket.State#004[1]: [              IP4( 2/0800) |    16 |      0 |     20 |   0 |     706 |       0 ]
		 * JPacket.State#004[2]: [              UDP( 5/0800) |    36 |      0 |      8 |   0 |     698 |       0 ]
		 * JPacket.State#004[3]: [              SIP(17/0800) |    44 |      0 |    698 |   0 |       0 |       0 ]
		 * 
		 * 
		 * Frame:
		 * Frame:                                  number = 4
		 * Frame:                               timestamp = 2012-06-23 04:54:35.005
		 * Frame:                             wire length = 742 bytes
		 * Frame:                         captured length = 742 bytes
		 * Frame:
		 * SLL:  ******* SLL - "Linux Cooked Capture" - offset=0 (0x0) length=16 protocol suite=LAN
		 * SLL: 
		 * SLL:                               packetType = 0
		 * SLL:                                   haType = 1
		 * SLL:                                 haLength = 6
		 * SLL:                                  address = 00:0c:29:03:74:83
		 * SLL:                                     type = 0x800 (2048)
		 * SLL: 
		 * Ip:  ******* Ip4 - "ip version 4" - offset=16 (0x10) length=20 protocol suite=NETWORK
		 * Ip: 
		 * Ip:                                  version = 4
		 * Ip:                                     hlen = 5 [5 * 4 = 20 bytes, No Ip Options]
		 * Ip:                                 diffserv = 0x0 (0)
		 * Ip:                    0000 00.. = [0] code point: not set
		 * Ip:                    .... ..0. = [0] ECN bit: not set
		 * Ip:                    .... ...0 = [0] ECE bit: not set
		 * Ip:                                   length = 726
		 * Ip:                                       id = 0x8343 (33603)
		 * Ip:                                    flags = 0x0 (0)
		 * Ip:                    0.. = [0] reserved
		 * Ip:                    .0. = [0] DF: do not fragment: not set
		 * Ip:                    ..0 = [0] MF: more fragments: not set
		 * Ip:                                   offset = 0
		 * Ip:                                      ttl = 64 [time to live]
		 * Ip:                                     type = 17 [next: User Datagram]
		 * Ip:                                 checksum = 0x116E (4462) [correct]
		 * Ip:                                   source = 10.30.103.140
		 * Ip:                              destination = 10.30.103.158
		 * Ip: 
		 * Udp:  ******* Udp offset=36 (0x24) length=8 
		 * Udp: 
		 * Udp:                                   source = 5090
		 * Udp:                              destination = 5060
		 * Udp:                                   length = 706
		 * Udp:                                 checksum = 0x3817 (14359) [correct]
		 * Udp: 
		 * Sip:  ******* Sip offset=44 (0x2C) length=698 
		 * Sip: 
		 * Sip:                            RequestMethod = BYE
		 * Sip:                               RequestUrl = sip:12345678@10.30.103.158:5060;transport=UDP
		 * Sip:                           RequestVersion = SIP/2.0
		 * Sip:                                      VIA = SIP/2.0/UDP 10.30.103.140:5090;rport;branch=z9hG4bKpXB7gt63KaK4F
		 * Sip:                             MAX-FORWARDS = 70
		 * Sip:                                     FROM = "eeeeeeugggg" <sip:6120@10.30.103.140>;tag=mjQrZSm4tS1DH
		 * Sip:                                       TO = <sip:12345678@10.30.103.158:5060>;tag=1213583113402945740001.0
		 * Sip:                                  CALL-ID = 66a26179-365d-1230-6191-000c2903746f
		 * Sip:                                     CSEQ = 29811223 BYE
		 * Sip:                                  CONTACT = <sip:gw+flip@10.30.103.140:5090;transport=udp;gw=flip>
		 * Sip:                               USER-AGENT = FreeSWITCH-mod_sofia/1.0.head-git-fb6e979 2011-08-26 04-48-33 +0000
		 * Sip:                                    ALLOW = INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, UPDATE, INFO, REGISTER, REFER, NOTIFY
		 * Sip:                                SUPPORTED = timer, precondition, path, replaces
		 * Sip:                           CONTENT-LENGTH = 0
		 * Sip:
		 * 
		 * </pre>
		 */
		final byte[] data = FormatUtils
				.toByteArray(""
						+ "000000010006000c2903748300000800450002d6834300004011116e0a1e678c0a1e"
						+ "679e13e213c402c23817425945207369703a31323334353637384031302e33302e31"
						+ "30332e3135383a353036303b7472616e73706f72743d554450205349502f322e300d"
						+ "0a5669613a205349502f322e302f5544502031302e33302e3130332e3134303a3530"
						+ "39303b72706f72743b6272616e63683d7a39684734624b70584237677436334b614b"
						+ "34460d0a4d61782d466f7277617264733a2037300d0a46726f6d3a20226565656565"
						+ "756767676722203c7369703a363132304031302e33302e3130332e3134303e3b7461"
						+ "673d6d6a51725a536d3474533144480d0a546f3a203c7369703a3132333435363738"
						+ "4031302e33302e3130332e3135383a353036303e3b7461673d313231333538333131"
						+ "333430323934353734303030312e300d0a43616c6c2d49443a203636613236313739"
						+ "2d333635642d313233302d363139312d3030306332393033373436660d0a43536571"
						+ "3a203239383131323233204259450d0a436f6e746163743a203c7369703a67772b66"
						+ "6c69704031302e33302e3130332e3134303a353039303b7472616e73706f72743d75"
						+ "64703b67773d666c69703e0d0a557365722d4167656e743a20467265655357495443"
						+ "482d6d6f645f736f6669612f312e302e686561642d6769742d666236653937392032"
						+ "3031312d30382d32362030342d34382d3333202b303030300d0a416c6c6f773a2049"
						+ "4e564954452c2041434b2c204259452c2043414e43454c2c204f5054494f4e532c20"
						+ "4d4553534147452c205550444154452c20494e464f2c2052454749535445522c2052"
						+ "454645522c204e4f544946590d0a537570706f727465643a2074696d65722c207072"
						+ "65636f6e646974696f6e2c20706174682c207265706c616365730d0a526561736f6e"
						+ "3a20512e3835303b63617573653d31363b746578743d224e4f524d414c5f434c4541"
						+ "52494e47220d0a436f6e74656e742d4c656e6774683a20300d0a0d0a");

		final JPacket packet = new JMemoryPacket(SLL.ID, data);
		out.println(packet.getState().toDebugString());
		out.println(packet);

		TestCase.assertTrue(packet.hasHeader(sip));
		TestCase.assertEquals(MessageType.REQUEST, sip.getMessageType());
		TestCase.assertTrue(sip.hasField(Sip.Request.RequestMethod));
		TestCase.assertEquals("BYE", sip.fieldValue(Sip.Request.RequestMethod));
		TestCase.assertEquals(Method.BYE, sip.getMethod());
		TestCase.assertTrue(sip.hasMethod(Method.BYE));
	}

	@Test
	public void testReadAllPackets() {
		String[] files = {"tests/test-sip-rtp.pcap",
				"tests/test-sip-rtp-g711.pcap",
				"tests/test-sip-info-packets.pcap"};

		int i = 1;
		Sip sip = new Sip();
		for (String file : files) {
			if (!new File(file).exists()) {
				continue;
			}
			out.println("================= " + file + " =================");
			for (JPacket packet : TestUtils.getIterable(file)) {

				if (packet.hasHeader(sip)) {
					System.out.println(packet.getState().toDebugString());
					if (sip.getMethod() == null) {
						out.println(sip);
					}
//					out.printf("#%d: method=%s type=%s%n", i++,
//							sip.getMethod(), sip.getMessageType());
				}
			}
		}
	}
}
