/*
 * Copyright (C) 2012 Sly Technologies, Inc.
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
package org.jnetpcap.protocol.sigtran;

import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * Payload Data (DATA) (0). The following format MUST be used for the DATA
 * chunk:
 * 
 * <pre>
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 0    | Reserved|U|B|E|    Length                     |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                              TSN                              |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |      Stream Identifier S      |   Stream Sequence Number n    |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                  Payload Protocol Identifier                  |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        \                                                               \
 *        /                 User Data (seq n of Stream S)                 /
 *        \                                                               \
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * @author Sly Technologies Inc.
 * @see RFC4960
 */
@Header(description = "Payload Data", suite = ProtocolSuite.SIGTRAN, nicname = "Sctp-data")
public class SctpData extends SctpChunk {
	
	/**
	 * Static numerical JRegistry generated ID for this protocol.
	 */
	public static final int ID = JProtocol.SCTP_DATA_ID;


	/**
	 * SCTP Payload Protocol Identifiers
	 * 
	 * @author Sly Technologies Inc.
	 * @see http 
	 *      ://www.iana.org/assignments/sctp-parameters/sctp-parameters.xml#sctp
	 *      -parameters-25
	 * @see RFC4960
	 */
	public enum SctpDataProtocol {

		/**
		 * Reserved by SCTP
		 * 
		 * @see RFC4960
		 */
		RESERVED1,

		/**
		 * IUA
		 * 
		 * @see RFC4233
		 */
		IUA,

		/**
		 * M2UA
		 * 
		 * @see RFC3331
		 */
		M2UA,

		/**
		 * M3UA
		 * 
		 * @see RFC4666
		 */
		M3UA,

		/**
		 * SUA
		 * 
		 * @see RFC3868
		 */
		SUA,

		/**
		 * M2PA
		 * 
		 * @see RFC4165
		 */
		M2PA,

		/**
		 * V5UA
		 * 
		 * @see RFC3807
		 */
		V5UA,

		/**
		 * H.248 - [ITU-T Recommendation H.248 Annex H, "Transport over SCTP",
		 * November 2000.]
		 * 
		 * 
		 */
		H248,

		/**
		 * BICC/Q.2150.3 - [ITU-T Recommendation Q.1902.1,
		 * "Bearer Independent Call Control protocol (Capability Set 2): Functional description"
		 * , July 2001.][ITU-T Recommendation Q.2150.3,
		 * "Signalling Transport Converter On SCTP", to be published.]
		 */
		BICC_Q21503,

		/**
		 * TALI
		 * 
		 * @see RFC3094
		 */
		TALI,

		/**
		 * DUA
		 * 
		 * @see RFC4129
		 */
		DUA,

		/**
		 * ASAP
		 * 
		 * @see RFC5352
		 */
		ASAP,

		/**
		 * ENRP
		 * 
		 * @see RFC5353
		 */
		ENRP,

		/**
		 * H.323 - [H.323 over SCTP October 2002.]
		 * 
		 * @see http://standard.pictel.com/ftp/avc-site/0206_Bru/AVD-2198.zip
		 */
		H323,

		/**
		 * Q.IPC/Q.2150.3 - [ITU-T Recommendation Q.2631.1
		 * "IP Connection Control Signaling Protocol - Capability Set 1", to be
		 * published.][ITU-T Recommendation Q.2150.3,
		 * "Signalling Transport Converter On SCTP", to be published.]
		 */
		QIPC_Q21503,

		/**
		 * SIMCO <draft-kiesel-midcom-simco-sctp-00.txt> - [Sebastian_Kiesel]
		 */
		SIMCO,

		/**
		 * DDP Segment Chunk
		 * 
		 * @see RFC5043
		 */
		DDP_SEGMENT,

		/**
		 * DDP Stream Session Control
		 * 
		 * @see RFC5403
		 */
		DDP_STREAM,

		/**
		 * S1 Application Protocol (S1AP)
		 * 
		 * @see http
		 *      ://www.3gpp.org/ftp/Specs/latest/Rel-8/23_series/23401-840.zip
		 */
		S1_APPLICATION,

		/**
		 * RUA -
		 * [http://www.3gpp.org/Specification-Numbering][http://www.3gpp.org
		 * /Specification-Numbering][John_Meredith]
		 */
		RUA,

		/**
		 * HNBAP - [http://www.3gpp.org/Specification-Numbering][TS
		 * 25.469][John_Meredith]
		 */
		HNBAP,

		/**
		 * ForCES-HP
		 * 
		 * @see RFC5811
		 */
		FORCES_HP,

		/**
		 * ForCES-MP
		 * 
		 * @see RFC5811
		 */
		FORCES_MP,

		/**
		 * ForCES-LP
		 * 
		 * @see RFC5811
		 */
		FORCES_LP,

		/**
		 * SBc-AP -
		 * [http://www.3gpp.org/Specification-Numbering][Kimmo_Kymalainen]
		 */
		SBC_AP,

		/**
		 * NBAP -
		 * [http://www.3gpp.org/Specification-Numbering][Kimmo_Kymalainen]
		 */
		NBAP,

		/**
		 * Unassigned
		 */
		RESERVED2,

		/**
		 * X2AP -
		 * [http://www.3gpp.org/Specification-Numbering][Kimmo_Kymalainen]
		 */
		X2AP,

		/**
		 * IRCP - Inter Router Capability Protocol - [Randall_Stewart]
		 */
		IRCP,

		/**
		 * LCS-AP -
		 * [http://www.3gpp.org/Specification-Numbering][Kimmo_Kymalainen]
		 */
		LCS_AP,

		/**
		 * MPICH2 -
		 * [Michael_Tuexen][http://www.mcs.anl.gov/research/projects/mpich2/]
		 */
		MPICH2,

		/**
		 * Service Area Broadcast Protocol (SABP)
		 * -[http://www.3gpp.org/Specification
		 * -Numbering][http://www.3gpp.org/Specification
		 * -Numbering][John_Meredith]
		 */
		SABP,

		/**
		 * Fractal Generator Protocol (FGP) -
		 * [Thomas_Dreibholz][http://tdrwww.iem.uni-due.de/dreibholz/rserpool/]
		 */
		FGP,

		/**
		 * Ping Pong Protocol (PPP) -
		 * [Thomas_Dreibholz][http://tdrwww.iem.uni-due.de/dreibholz/rserpool/]
		 */
		PPP,

		/**
		 * CalcApp Protocol (CALCAPP) -
		 * [Thomas_Dreibholz][http://tdrwww.iem.uni-due.de/dreibholz/rserpool/]
		 */
		CALCAPP,

		/**
		 * Scripting Service Protocol (SSP) -
		 * [Thomas_Dreibholz][http://tdrwww.iem.uni-due.de/dreibholz/rserpool/]
		 */
		SSP,

		/**
		 * NetPerfMeter Protocol Control Channel (NPMP-CONTROL) -
		 * [Thomas_Dreibholz][http://www.iem.uni-due.de/~dreibh/netperfmeter/]
		 */
		NPMP_CONTROL,

		/**
		 * NetPerfMeter Protocol Data Channel (NPMP-DATA) -
		 * [Thomas_Dreibholz][http://www.iem.uni-due.de/~dreibh/netperfmeter/]
		 */
		NPMP_DATA,

		/**
		 * Echo (ECHO) -
		 * [Thomas_Dreibholz][http://tdrwww.iem.uni-due.de/dreibholz/rserpool/]
		 */
		ECHO,

		/**
		 * Discard (DISCARD) -
		 * [Thomas_Dreibholz][http://tdrwww.iem.uni-due.de/dreibholz/rserpool/]
		 */
		DISCARD,

		/**
		 * Daytime (DAYTIME) -
		 * [Thomas_Dreibholz][http://tdrwww.iem.uni-due.de/dreibholz/rserpool/]
		 */
		DAYTIME,

		/**
		 * Character Generator (CHARGEN) -
		 * [Thomas_Dreibholz][http://tdrwww.iem.uni-due.de/dreibholz/rserpool/]
		 */
		CHARGEN,

		/**
		 * 3GPP RNA -
		 * [Tonesi][http://www.3gpp.org/ftp/specs/html-info/25471.htm]
		 */
		RNA_3GPP,

		/**
		 * 3GPP M2AP -
		 * [Tonesi][http://www.3gpp.org/ftp/specs/html-info/36442.htm
		 * ][http://www.3gpp.org/ftp/specs/html-info/36443.htm]
		 */
		M2AP_3GPP,

		/**
		 * SSH over SCTP - [Michael_Tuexen]
		 */
		SSH,

		/**
		 * Diameter in a SCTP DATA chunk
		 * 
		 * @see http://tools.ietf.org/html/draft-ietf-dime-rfc3588bis-33
		 */
		DIAMETER_DATA,

		/**
		 * Diameter in a DTLS/SCTP DATA chunk
		 * 
		 * @see http://tools.ietf.org/html/draft-ietf-dime-rfc3588bis-33
		 */
		DIAMETER_DTLS;

		/**
		 * Converts integer protocol to a name
		 * 
		 * @param protocol
		 *            protocol to convert
		 * @return name as a string
		 */
		public static String valueOf(int protocol) {
			if (protocol < values().length) {
				return values()[protocol].toString();
			} else {
				return "Unassigned";
			}
		}

	}

	/**
	 * U bit: 1 bit
	 * <p>
	 * The (U)nordered bit, if set to '1', indicates that this is an unordered
	 * DATA chunk, and there is no Stream Sequence Number assigned to this DATA
	 * chunk. Therefore, the receiver MUST ignore the Stream Sequence Number
	 * field.
	 * </p>
	 * </p> After reassembly (if necessary), unordered DATA chunks MUST be
	 * dispatched to the upper layer by the receiver without any attempt to
	 * reorder. </p></p> If an unordered user message is fragmented, each
	 * fragment of the message MUST have its U bit set to '1'. </p>
	 */
	public final static int CHUNK_DATA_UNORDERED_FLAG = 0x4;

	/**
	 * B bit: 1 bit
	 * <p>
	 * The (B)eginning fragment bit, if set, indicates the first fragment of a
	 * user message.
	 * </p>
	 */
	public final static int CHUNK_DATA_BEGINNING_FRAGMENT_FLAG = 0x2;

	/**
	 * E bit: 1 bit
	 * <p>
	 * The (E)nding fragment bit, if set, indicates the last fragment of a user
	 * message.
	 * </p>
	 */
	public final static int CHUNK_DATA_ENDING_FRAMGNET_FLAG = 0x1;

	/**
	 * /** B bit: 1 bit
	 * <p>
	 * The (B)eginning fragment bit, if set, indicates the first fragment of a
	 * user message.
	 * </p>
	 * 
	 * @return state of the B data chunk flag
	 */
	@Field(parent = "flags", display = " B: Beginnning fragment", offset = 1, length = 1)
	public int flags_B() {
		return (flags() & CHUNK_DATA_BEGINNING_FRAGMENT_FLAG) >> 1;
	}

	/**
	 * Returns a description of the current state of B flag
	 * 
	 * @return description
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String flags_BDescription() {
		switch (flags_B()) {
			case 0 :
				return "no";
			case 1 :
				return "yes";
		}
		return "unknown option";
	}

	/**
	 * U bit: 1 bit
	 * <p>
	 * The (U)nordered bit, if set to '1', indicates that this is an unordered
	 * DATA chunk, and there is no Stream Sequence Number assigned to this DATA
	 * chunk. Therefore, the receiver MUST ignore the Stream Sequence Number
	 * field.
	 * </p>
	 * </p> After reassembly (if necessary), unordered DATA chunks MUST be
	 * dispatched to the upper layer by the receiver without any attempt to
	 * reorder. </p></p> If an unordered user message is fragmented, each
	 * fragment of the message MUST have its U bit set to '1'. </p>
	 * 
	 * @return state of the U data chunk flag
	 */
	@Field(parent = "flags", display = "BE: Fragmentation", offset = 0, length = 2)
	public int flags_BE() {
		return (flags() & (CHUNK_DATA_BEGINNING_FRAGMENT_FLAG |CHUNK_DATA_ENDING_FRAMGNET_FLAG)) >> 0;
	}

	/**
	 * Returns a description of the current state of U flag
	 * 
	 * @return description
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String flags_BEDescription() {
		switch (flags_BE()) {
			case  0:
				return "Middle piece of a fragmented user message";
			case 1 :
				return "Last piece of a fragmented user message";
			case 2 :
				return "First piece of a fragmented user message";
			case 3 :
				return "Unfragmented message";
		}
		return "unknown option";
	}

	/**
	 * E bit: 1 bit
	 * <p>
	 * The (E)nding fragment bit, if set, indicates the last fragment of a user
	 * message.
	 * </p>
	 * 
	 * @return state of the E data chunk flag
	 */
	@Field(parent = "flags", display = " E: Ending fragment", offset = 0, length = 1)
	public int flags_E() {
		return (flags() & CHUNK_DATA_ENDING_FRAMGNET_FLAG) >> 0;
	}

	/**
	 * Returns a description of the current state of E flag
	 * 
	 * @return description
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String flags_EDescription() {
		switch (flags_E()) {
			case 0 :
				return "no";
			case 1 :
				return "yes";
		}
		return "unknown option";
	}

	/**
	 * U bit: 1 bit
	 * <p>
	 * The (U)nordered bit, if set to '1', indicates that this is an unordered
	 * DATA chunk, and there is no Stream Sequence Number assigned to this DATA
	 * chunk. Therefore, the receiver MUST ignore the Stream Sequence Number
	 * field.
	 * </p>
	 * </p> After reassembly (if necessary), unordered DATA chunks MUST be
	 * dispatched to the upper layer by the receiver without any attempt to
	 * reorder. </p></p> If an unordered user message is fragmented, each
	 * fragment of the message MUST have its U bit set to '1'. </p>
	 * 
	 * @return state of the U data chunk flag
	 */
	@Field(parent = "flags", display = " U: Data ordering", offset = 2, length = 1)
	public int flags_U() {
		return (flags() & CHUNK_DATA_UNORDERED_FLAG) >> 2;
	}
	
	/**
	 * Returns a description of the current state of U flag
	 * 
	 * @return description
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String flags_UDescription() {
		switch (flags_U()) {
			case 0 :
				return "ordered";
			case 1 :
				return "unordered";
		}
		return "unknown option";
	}
	/**
	 * 
	 * @return
	 * @see http://www.iana.org/assignments/sctp-parameters/sctp-parameters.xml
	 */
	@Field(offset = 12 * BYTE, length = 4 * BYTE, format = "%d")
	public long protocol() {
		return super.getUInt(12);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String protocolDescription() {
		return protocol() == 0 ? "not specified" : SctpDataProtocol
				.valueOf((int) protocol());
	}

	@Field(offset = 8 * BYTE, length = 2 * BYTE, format = "%d")
	public int streamId() {
		return super.getUShort(8);
	}

	@Field(offset = 10 * BYTE, length = 2 * BYTE, format = "%d")
	public int streamSequence() {
		return super.getUShort(10);
	}

	@Field(offset = 4 * BYTE, length = 4 * BYTE, format = "%x")
	public long tsn() {
		return super.getUInt(4);
	}

	public void tsn(long value) {
		super.setUInt(4, value);
	}
}
