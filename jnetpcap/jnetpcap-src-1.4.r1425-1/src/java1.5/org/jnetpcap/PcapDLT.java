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
package org.jnetpcap;

// TODO: Auto-generated Javadoc
/**
 * <p>Constants that represent the Pcap's Payload Link Type assignments. The most
 * popular constant is the {@link #EN10MB} (alternatively {@link #CONST_EN10MB})
 *  which represents
 * <em>Ethernet2</em> based physical medium. This includes 10, 100, and 1000
 * mega-bit ethernets.</p>
 * <p>
 * There are 2 tables within PcapDLT enum structure. First is the full table of
 * enum constants, and then there is a duplicate table containing 
 * <code>public final static int</code> of contants, prefixed with 
 * <code>CONST_</code>. Also the enum constant's field <code>value</code> is
 * public which means that integer DLT constant can also be access using the
 * field directly.
 * </p> 
 * Here are 4 examples of how you can use DLT constants in various ways.
 * 
 * <h2>Accessing the int DLT value using an enum constant</h2>
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * if (dlt == PcapDLT.EN10MB.value) {
 * 	 // Do something
 * }
 * 
 * // Also can use this more formal approach
 * 
 * if (PcapDLT.EN10MB.equals(dlt)) {
 *   // Do something
 * } 
 * </pre>
 * 
 * <h2>Accessing the int DLT value from integer constants table</h2>
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * if (dlt == PcapDLT.CONST_EN10MB) {
 * 	// Do something
 * }
 * </pre>
 * 
 * <h2>Converting integer DLT value into a constant</h2>
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * PcapDLT enumConst = PcapDLT.valueOf(dlt);
 * System.out.println("The Payload Link Type is " + enumConst + " described as " + 
 * 		enumConst.description);
 * </pre> 
 * 
 * <h2>Converting string DLT name into a constant</h2>
 * <pre>
 * PcapDLT enumConst = PcapDLT.valueOf("EN10MB");
 * System.out.println("The Payload Link Type value is " + enumConst.value);
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("all")
public enum PcapDLT implements DataLinkType {
  
  /** The NULL. */
  NULL(0),
  
  /** The E n10 mb. */
  EN10MB(1),
  
  /** The E n3 mb. */
  EN3MB(2),
  
  /** The A x25. */
  AX25(3),
  
  /** The PRONET. */
  PRONET(4),
  
  /** The CHAOS. */
  CHAOS(5),
  
  /** The IEE e802. */
  IEEE802(6),
  
  /** The ARCNET. */
  ARCNET(7),
  
  /** The SLIP. */
  SLIP(8),
  
  /** The PPP. */
  PPP(9),
  
  /** The FDDI. */
  FDDI(10),
  
  /** The AT m_ rf c1483. */
  ATM_RFC1483(11),
  
  /** The RAW. */
  RAW(12),
  
  /** The SLI p_ bsdos. */
  SLIP_BSDOS(15),
  
  /** The PP p_ bsdos. */
  PPP_BSDOS(16),
  
  /** The AT m_ clip. */
  ATM_CLIP(19),
  
  /** The PP p_ serial. */
  PPP_SERIAL(50),
  
  /** The PP p_ ether. */
  PPP_ETHER(51),
  
  /** The SYMANTE c_ firewall. */
  SYMANTEC_FIREWALL(99),
  
  /** The C_ hdlc. */
  C_HDLC(104),
  
  /** The IEE e802_11. */
  IEEE802_11(105),
  
  /** The FRELAY. */
  FRELAY(107),
  
  /** The LOOP. */
  LOOP(108),
  
  /** The ENC. */
  ENC(109),
  
  /** The LINU x_ sll. */
  LINUX_SLL(113),
  
  /** The LTALK. */
  LTALK(114),
  
  /** The ECONET. */
  ECONET(115),
  
  /** The IPFILTER. */
  IPFILTER(116),
  
  /** The PFLOG. */
  PFLOG(117),
  
  /** The CISC o_ ios. */
  CISCO_IOS(118),
  
  /** The PRIS m_ header. */
  PRISM_HEADER(119),
  
  /** The AIRONE t_ header. */
  AIRONET_HEADER(120),
  
  /** The PFSYNC. */
  PFSYNC(121),
  
  /** The I p_ ove r_ fc. */
  IP_OVER_FC(122),
  
  /** The SUNATM. */
  SUNATM(123),
  
  /** The RIO. */
  RIO(124),
  
  /** The PC i_ exp. */
  PCI_EXP(125),
  
  /** The AURORA. */
  AURORA(126),
  
  /** The IEE e802_11_ radio. */
  IEEE802_11_RADIO(127),
  
  /** The TZSP. */
  TZSP(128),
  
  /** The ARCNE t_ linux. */
  ARCNET_LINUX(129),
  
  /** The JUNIPE r_ mlppp. */
  JUNIPER_MLPPP(130),
  
  /** The JUNIPE r_ mlfr. */
  JUNIPER_MLFR(131),
  
  /** The JUNIPE r_ es. */
  JUNIPER_ES(132),
  
  /** The JUNIPE r_ ggsn. */
  JUNIPER_GGSN(133),
  
  /** The JUNIPE r_ mfr. */
  JUNIPER_MFR(134),
  
  /** The JUNIPE r_ at m2. */
  JUNIPER_ATM2(135),
  
  /** The JUNIPE r_ services. */
  JUNIPER_SERVICES(136),
  
  /** The JUNIPE r_ at m1. */
  JUNIPER_ATM1(137),
  
  /** The APPL e_ i p_ ove r_ iee e1394. */
  APPLE_IP_OVER_IEEE1394(138),
  
  /** The MT p2_ wit h_ phdr. */
  MTP2_WITH_PHDR(139),
  
  /** The MT p2. */
  MTP2(140),
  
  /** The MT p3. */
  MTP3(141),
  
  /** The SCCP. */
  SCCP(142),
  
  /** The DOCSIS. */
  DOCSIS(143),
  
  /** The LINU x_ irda. */
  LINUX_IRDA(144),
  
  /** The IB m_ sp. */
  IBM_SP(145),
  
  /** The IB m_ sn. */
  IBM_SN(146),
  
  /** The USE r0. */
  USER0(147),
  
  /** The USE r1. */
  USER1(148),
  
  /** The USE r2. */
  USER2(149),
  
  /** The USE r3. */
  USER3(150),
  
  /** The USE r4. */
  USER4(151),
  
  /** The USE r5. */
  USER5(152),
  
  /** The USE r6. */
  USER6(153),
  
  /** The USE r7. */
  USER7(154),
  
  /** The USE r8. */
  USER8(155),
  
  /** The USE r9. */
  USER9(156),
  
  /** The USE r10. */
  USER10(157),
  
  /** The USE r11. */
  USER11(158),
  
  /** The USE r12. */
  USER12(159),
  
  /** The USE r13. */
  USER13(160),
  
  /** The USE r14. */
  USER14(161),
  
  /** The USE r15. */
  USER15(162),
  
  /** The IEE e802_11_ radi o_ avs. */
  IEEE802_11_RADIO_AVS(163),
  
  /** The JUNIPE r_ monitor. */
  JUNIPER_MONITOR(164),
  
  /** The BACNE t_ m s_ tp. */
  BACNET_MS_TP(165),
  
  /** The PP p_ pppd. */
  PPP_PPPD(166),
  
  /** The JUNIPE r_ pppoe. */
  JUNIPER_PPPOE(167),
  
  /** The JUNIPE r_ pppo e_ atm. */
  JUNIPER_PPPOE_ATM(168),
  
  /** The GPR s_ llc. */
  GPRS_LLC(169),
  
  /** The GP f_ t. */
  GPF_T(170),
  
  /** The GP f_ f. */
  GPF_F(171),
  
  /** The GCO m_ t1 e1. */
  GCOM_T1E1(172),
  
  /** The GCO m_ serial. */
  GCOM_SERIAL(173),
  
  /** The JUNIPE r_ pi c_ peer. */
  JUNIPER_PIC_PEER(174),
  
  /** The ER f_ eth. */
  ERF_ETH(175),
  
  /** The ER f_ pos. */
  ERF_POS(176),
  
  /** The LINU x_ lapd. */
  LINUX_LAPD(177),
	
	;
	
  /** Integer dlt value assigned by libpcap to this constant. */
	public final int value;
	
	/**
	 * Description of the dlt retrieved by quering the native pcap library. The
	 * description is not a static constant part of the API and may change from
	 * native libpcap implementation to implementation.
	 */
	public final String description;

	/**
	 * Instantiates a new pcap dlt.
	 * 
	 * @param value
	 *          the value
	 */
	private PcapDLT(int value) {
		this.value = value;
		
		// Assign description by quering the native Libpcap library
		String str = Pcap.datalinkValToDescription(value);
		if (str == null) {
			str = name();
		}
		
		this.description = str;
		
	}
	
	/**
	 * Compares the supplied value with the constant's assigned DLT value.
	 * 
	 * @param value
	 *          the value
	 * @return true if the supplied value matches the value of the constant,
	 *         otherwise false value value to check against this constant
	 */
	public boolean equals(int value) {
		return this.value == value;
	}
	
	/**
	 * Converts an integer value into a PcapDLT constant.
	 * @param value Pcap DLT integer value to convert
	 * @return constant assigned to the DLT integer, or null if not found
	 */
	public static PcapDLT valueOf(int value) {
		final PcapDLT[] values = values();
		final int length = values.length;
		
		for (int i = 0; i < length; i++) {
	    if (values[i].value == value) {
	    	return values[i];
	    }
	    
    }
		
		return null;
	}
	
	/** The Constant CONST_NULL. */
	public final static int CONST_NULL = 0;

	/** The Constant CONST_EN10MB. */
	public final static int CONST_EN10MB = 1;

	/** The Constant CONST_EN3MB. */
	public final static int CONST_EN3MB = 2;

	/** The Constant CONST_AX25. */
	public final static int CONST_AX25 = 3;

	/** The Constant CONST_PRONET. */
	public final static int CONST_PRONET = 4;

	/** The Constant CONST_CHAOS. */
	public final static int CONST_CHAOS = 5;

	/** The Constant CONST_IEEE802. */
	public final static int CONST_IEEE802 = 6;

	/** The Constant CONST_ARCNET. */
	public final static int CONST_ARCNET = 7;

	/** The Constant CONST_SLIP. */
	public final static int CONST_SLIP = 8;

	/** The Constant CONST_PPP. */
	public final static int CONST_PPP = 9;

	/** The Constant CONST_FDDI. */
	public final static int CONST_FDDI = 10;

	/** The Constant CONST_ATM_RFC1483. */
	public final static int CONST_ATM_RFC1483 = 11;

	/** The Constant CONST_RAW. */
	public final static int CONST_RAW = 12;

	/** The Constant CONST_SLIP_BSDOS. */
	public final static int CONST_SLIP_BSDOS = 15;

	/** The Constant CONST_PPP_BSDOS. */
	public final static int CONST_PPP_BSDOS = 16;

	/** The Constant CONST_ATM_CLIP. */
	public final static int CONST_ATM_CLIP = 19;

	/** The Constant CONST_PPP_SERIAL. */
	public final static int CONST_PPP_SERIAL = 50;

	/** The Constant CONST_PPP_ETHER. */
	public final static int CONST_PPP_ETHER = 51;

	/** The Constant CONST_SYMANTEC_FIREWALL. */
	public final static int CONST_SYMANTEC_FIREWALL = 99;

	/** The Constant CONST_C_HDLC. */
	public final static int CONST_C_HDLC = 104;

	/** The Constant CONST_IEEE802_11. */
	public final static int CONST_IEEE802_11 = 105;

	/** The Constant CONST_FRELAY. */
	public final static int CONST_FRELAY = 107;

	/** The Constant CONST_LOOP. */
	public final static int CONST_LOOP = 108;

	/** The Constant CONST_ENC. */
	public final static int CONST_ENC = 109;

	/** The Constant CONST_LINUX_SLL. */
	public final static int CONST_LINUX_SLL = 113;

	/** The Constant CONST_LTALK. */
	public final static int CONST_LTALK = 114;

	/** The Constant CONST_ECONET. */
	public final static int CONST_ECONET = 115;

	/** The Constant CONST_IPFILTER. */
	public final static int CONST_IPFILTER = 116;

	/** The Constant CONST_PFLOG. */
	public final static int CONST_PFLOG = 117;

	/** The Constant CONST_CISCO_IOS. */
	public final static int CONST_CISCO_IOS = 118;

	/** The Constant CONST_PRISM_HEADER. */
	public final static int CONST_PRISM_HEADER = 119;

	/** The Constant CONST_AIRONET_HEADER. */
	public final static int CONST_AIRONET_HEADER = 120;

	/** The Constant CONST_PFSYNC. */
	public final static int CONST_PFSYNC = 121;

	/** The Constant CONST_IP_OVER_FC. */
	public final static int CONST_IP_OVER_FC = 122;

	/** The Constant CONST_SUNATM. */
	public final static int CONST_SUNATM = 123;

	/** The Constant CONST_RIO. */
	public final static int CONST_RIO = 124;

	/** The Constant CONST_PCI_EXP. */
	public final static int CONST_PCI_EXP = 125;

	/** The Constant CONST_AURORA. */
	public final static int CONST_AURORA = 126;

	/** The Constant CONST_IEEE802_11_RADIO. */
	public final static int CONST_IEEE802_11_RADIO = 127;

	/** The Constant CONST_TZSP. */
	public final static int CONST_TZSP = 128;

	/** The Constant CONST_ARCNET_LINUX. */
	public final static int CONST_ARCNET_LINUX = 129;

	/** The Constant CONST_JUNIPER_MLPPP. */
	public final static int CONST_JUNIPER_MLPPP = 130;

	/** The Constant CONST_APPLE_IP_OVER_IEEE1394. */
	public final static int CONST_APPLE_IP_OVER_IEEE1394 = 138;

	/** The Constant CONST_JUNIPER_MLFR. */
	public final static int CONST_JUNIPER_MLFR = 131;

	/** The Constant CONST_JUNIPER_ES. */
	public final static int CONST_JUNIPER_ES = 132;

	/** The Constant CONST_JUNIPER_GGSN. */
	public final static int CONST_JUNIPER_GGSN = 133;

	/** The Constant CONST_JUNIPER_MFR. */
	public final static int CONST_JUNIPER_MFR = 134;

	/** The Constant CONST_JUNIPER_ATM2. */
	public final static int CONST_JUNIPER_ATM2 = 135;

	/** The Constant CONST_JUNIPER_SERVICES. */
	public final static int CONST_JUNIPER_SERVICES = 136;

	/** The Constant CONST_JUNIPER_ATM1. */
	public final static int CONST_JUNIPER_ATM1 = 137;

	/** The Constant CONST_MTP2_WITH_PHDR. */
	public final static int CONST_MTP2_WITH_PHDR = 139;

	/** The Constant CONST_MTP2. */
	public final static int CONST_MTP2 = 140;

	/** The Constant CONST_MTP3. */
	public final static int CONST_MTP3 = 141;

	/** The Constant CONST_SCCP. */
	public final static int CONST_SCCP = 142;

	/** The Constant CONST_DOCSIS. */
	public final static int CONST_DOCSIS = 143;

	/** The Constant CONST_LINUX_IRDA. */
	public final static int CONST_LINUX_IRDA = 144;

	/** The Constant CONST_IBM_SP. */
	public final static int CONST_IBM_SP = 145;

	/** The Constant CONST_IBM_SN. */
	public final static int CONST_IBM_SN = 146;

	/** The Constant CONST_USER0. */
	public final static int CONST_USER0 = 147;

	/** The Constant CONST_USER1. */
	public final static int CONST_USER1 = 148;

	/** The Constant CONST_USER2. */
	public final static int CONST_USER2 = 149;

	/** The Constant CONST_USER3. */
	public final static int CONST_USER3 = 150;

	/** The Constant CONST_USER4. */
	public final static int CONST_USER4 = 151;

	/** The Constant CONST_USER5. */
	public final static int CONST_USER5 = 152;

	/** The Constant CONST_USER6. */
	public final static int CONST_USER6 = 153;

	/** The Constant CONST_USER7. */
	public final static int CONST_USER7 = 154;

	/** The Constant CONST_USER8. */
	public final static int CONST_USER8 = 155;

	/** The Constant CONST_USER9. */
	public final static int CONST_USER9 = 156;

	/** The Constant CONST_USER10. */
	public final static int CONST_USER10 = 157;

	/** The Constant CONST_USER11. */
	public final static int CONST_USER11 = 158;

	/** The Constant CONST_USER12. */
	public final static int CONST_USER12 = 159;

	/** The Constant CONST_USER13. */
	public final static int CONST_USER13 = 160;

	/** The Constant CONST_USER14. */
	public final static int CONST_USER14 = 161;

	/** The Constant CONST_USER15. */
	public final static int CONST_USER15 = 162;

	/** The Constant CONST_IEEE802_11_RADIO_AVS. */
	public final static int CONST_IEEE802_11_RADIO_AVS = 163;

	/** The Constant CONST_JUNIPER_MONITOR. */
	public final static int CONST_JUNIPER_MONITOR = 164;

	/** The Constant CONST_BACNET_MS_TP. */
	public final static int CONST_BACNET_MS_TP = 165;

	/** The Constant CONST_PPP_PPPD. */
	public final static int CONST_PPP_PPPD = 166;

	/** The Constant CONST_JUNIPER_PPPOE. */
	public final static int CONST_JUNIPER_PPPOE = 167;

	/** The Constant CONST_JUNIPER_PPPOE_ATM. */
	public final static int CONST_JUNIPER_PPPOE_ATM = 168;

	/** The Constant CONST_GPRS_LLC. */
	public final static int CONST_GPRS_LLC = 169;

	/** The Constant CONST_GPF_T. */
	public final static int CONST_GPF_T = 170;

	/** The Constant CONST_GPF_F. */
	public final static int CONST_GPF_F = 171;

	/** The Constant CONST_GCOM_T1E1. */
	public final static int CONST_GCOM_T1E1 = 172;

	/** The Constant CONST_GCOM_SERIAL. */
	public final static int CONST_GCOM_SERIAL = 173;

	/** The Constant CONST_JUNIPER_PIC_PEER. */
	public final static int CONST_JUNIPER_PIC_PEER = 174;

	/** The Constant CONST_ERF_ETH. */
	public final static int CONST_ERF_ETH = 175;

	/** The Constant CONST_ERF_POS. */
	public final static int CONST_ERF_POS = 176;

	/** The Constant CONST_LINUX_LAPD. */
	public final static int CONST_LINUX_LAPD = 177;

	/* (non-Javadoc)
   * @see org.jnetpcap.DataLinkType#getDescription()
   */
  /**
	 * Gets the description of the dlt retrieved by quering the native pcap
	 * library.
	 * 
	 * @return the description of the dlt retrieved by quering the native pcap
	 *         library
	 * @see org.jnetpcap.DataLinkType#getDescription()
	 */
	public String getDescription() {
	  return this.description;
  }

	/* (non-Javadoc)
   * @see org.jnetpcap.DataLinkType#getValue()
   */
  /**
	 * Gets the integer dlt value assigned by libpcap to this constant.
	 * 
	 * @return the integer dlt value assigned by libpcap to this constant
	 * @see org.jnetpcap.DataLinkType#getValue()
	 */
	public int getValue() {
	  return this.value;
  }
}
