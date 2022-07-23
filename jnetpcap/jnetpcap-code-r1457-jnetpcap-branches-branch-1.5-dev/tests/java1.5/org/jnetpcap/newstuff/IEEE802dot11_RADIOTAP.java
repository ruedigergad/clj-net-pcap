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
package org.jnetpcap.newstuff;

import java.nio.ByteOrder;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScan;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.Scanner;

// TODO: Auto-generated Javadoc
/**
 * IEEE 802.11 Radiotap - Header definition
 * 
 * @author David Gutzmann
 * @author Freie Universit&auml;t Berlin
 */

@Header(name = "IEEE 802.11 Radiotap", nicname = "radiotap", dlt = PcapDLT.IEEE802_11_RADIO)
public class IEEE802dot11_RADIOTAP
    extends JHeaderMap<IEEE802dot11_RADIOTAP> {

	/**
	 * Baseclass for all Radiotap data fields sub-headers
	 */
	public static abstract class DataField
	    extends JSubHeader<IEEE802dot11_RADIOTAP> {

		/**
		 * Instantiates a new data field.
		 */
		protected DataField() {
			order(ByteOrder.LITTLE_ENDIAN);
		}

		// TODO: Sub-Headers???
	}

	/**
	 * The Class DataField_TSFT.
	 */
	@Header(id = 1)
	public static class DataField_TSFT
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 64;
		}

		/**
		 * Value in microseconds of the MAC's 64-bit 802.11 Time Synchronization
		 * Function timer when the first bit of the MPDU arrived at the MAC. For
		 * received frames, only.
		 */
		@Field(format = "%d", offset = 0, length = 64)
		public long TSFT() {
			return super.getLong(0); /* 64bits unsigned */
		}

	}

	/**
	 * The Class DataField_Flags.
	 */
	@Header(id = 2)
	public static class DataField_Flags
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 8;
		}

		/**
		 * Properties of received frames. See IEEE80211_RADIOTAP_F_* flags defined.
		 */
		@Field(format = "%x", offset = 0, length = 8)
		public int Flags() {
			return super.getUByte(0); /* 8bits unsigned */
		}

		/**
		 * Flags_ cfp.
		 * 
		 * @return the int
		 */
		@Field(parent = "Flags", offset = 0, length = 1, display = "sent/recieved during CFP")
		public int Flags_CFP() {
			return (Flags() & IEEE80211_RADIOTAP_F_CFP) >> 0;
		}

		/**
		 * Flags_ shortpre.
		 * 
		 * @return the int
		 */
		@Field(parent = "Flags", offset = 1, length = 1, display = "sent/received with short preamble")
		public int Flags_SHORTPRE() {
			return (Flags() & IEEE80211_RADIOTAP_F_SHORTPRE) >> 1;
		}

		/**
		 * Flags_ wep.
		 * 
		 * @return the int
		 */
		@Field(parent = "Flags", offset = 2, length = 1, display = "sent/received with WEP encryption")
		public int Flags_WEP() {
			return (Flags() & IEEE80211_RADIOTAP_F_WEP) >> 2;
		}

		/**
		 * Flags_ frag.
		 * 
		 * @return the int
		 */
		@Field(parent = "Flags", offset = 3, length = 1, display = "sent/received with fragmentation")
		public int Flags_FRAG() {
			return (Flags() & IEEE80211_RADIOTAP_F_FRAG) >> 3;
		}

		/**
		 * Flags_ fcs.
		 * 
		 * @return the int
		 */
		@Field(parent = "Flags", offset = 4, length = 1, display = "frame includes FCS")
		public int Flags_FCS() {
			return (Flags() & IEEE80211_RADIOTAP_F_FCS) >> 4;
		}

		/**
		 * Flags_ datapad.
		 * 
		 * @return the int
		 */
		@Field(parent = "Flags", offset = 5, length = 1, display = "frame has padding between 802.11 header and payload (to 32-bit boundary)")
		public int Flags_DATAPAD() {
			return (Flags() & IEEE80211_RADIOTAP_F_DATAPAD) >> 5;
		}

	}

	/**
	 * The Class DataField_Rate.
	 */
	@Header(id = 3)
	public static class DataField_Rate
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 8;
		}

		/**
		 * Tx/Rx data rate
		 * 
		 * @return The data Rate in 500kb/s
		 */
		@Field(format = "%d", offset = 0, length = 8)
		public int Rate() {
			return super.getUByte(0); /* 8bits unsigned */
		}

		/**
		 * Rate description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String RateDescription() {
			return Rate() * 500 + " Kbps";
		}

	}

	/**
	 * The Class DataField_Channel.
	 */
	@Header(id = 4)
	public static class DataField_Channel
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 32;
		}

		/**
		 * Tx/Rx frequency in MHz
		 */
		@Field(offset = 0, format = "%d", length = 16)
		public int Channel() {
			return super.getUShort(0); /* 16bits unsigned */
		}

		/**
		 * Channel description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String ChannelDescription() {
			return Channel() + " MHz";
		}

		/**
		 * Properties of the Channel. See IEEE80211_RADIOTAP_CHAN_* flags defined.
		 */
		@Field(format = "%x", offset = 2 * 8, length = 16)
		public int ChannelFlags() {
			return super.getUShort(2); /* 16bits unsigned */
		}

		/**
		 * Channel flags_ turbo.
		 * 
		 * @return the int
		 */
		@Field(parent = "ChannelFlags", offset = 4, length = 1, display = "Turbo channel")
		public int ChannelFlags_TURBO() {
			return (ChannelFlags() & IEEE80211_RADIOTAP_CHAN_TURBO) >> 4;
		}

		/**
		 * Channel flags_ cck.
		 * 
		 * @return the int
		 */
		@Field(parent = "ChannelFlags", offset = 5, length = 1, display = "CCK channel")
		public int ChannelFlags_CCK() {
			return (ChannelFlags() & IEEE80211_RADIOTAP_CHAN_CCK) >> 5;
		}

		/**
		 * Channel flags_ ofdm.
		 * 
		 * @return the int
		 */
		@Field(parent = "ChannelFlags", offset = 6, length = 1, display = "OFDM channel")
		public int ChannelFlags_OFDM() {
			return (ChannelFlags() & IEEE80211_RADIOTAP_CHAN_OFDM) >> 6;
		}

		/**
		 * Channel flags_2 g hz.
		 * 
		 * @return the int
		 */
		@Field(parent = "ChannelFlags", offset = 7, length = 1, display = "2GHz channel")
		public int ChannelFlags_2GHz() {
			return (ChannelFlags() & IEEE80211_RADIOTAP_CHAN_2GHZ) >> 7;
		}

		/**
		 * Channel flags_5 g hz.
		 * 
		 * @return the int
		 */
		@Field(parent = "ChannelFlags", offset = 8, length = 1, display = "5GHz channel")
		public int ChannelFlags_5GHz() {
			return (ChannelFlags() & IEEE80211_RADIOTAP_CHAN_5GHZ) >> 8;
		}

		/**
		 * Channel flags_ passive.
		 * 
		 * @return the int
		 */
		@Field(parent = "ChannelFlags", offset = 9, length = 1, display = "Only passive scan allowed")
		public int ChannelFlags_PASSIVE() {
			return (ChannelFlags() & IEEE80211_RADIOTAP_CHAN_PASSIVE) >> 9;
		}

		/**
		 * Channel flags_ dyn.
		 * 
		 * @return the int
		 */
		@Field(parent = "ChannelFlags", offset = 10, length = 1, display = "Dynamic CCK-OFDM channel")
		public int ChannelFlags_DYN() {
			return (ChannelFlags() & IEEE80211_RADIOTAP_CHAN_DYN) >> 10;
		}

		/**
		 * Channel flags_ gfsk.
		 * 
		 * @return the int
		 */
		@Field(parent = "ChannelFlags", offset = 11, length = 1, display = "GFSK channel (FHSS PHY) ")
		public int ChannelFlags_GFSK() {
			return (ChannelFlags() & IEEE80211_RADIOTAP_CHAN_GFSK) >> 11;
		}
	}

	/**
	 * The Class DataField_FHSS.
	 */
	@Header(id = 5)
	public static class DataField_FHSS
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 16;
		}

		/**
		 * For frequency-hopping radios, the hop set (first byte) and pattern
		 * (second byte).
		 */
		@Field(format = "%x", offset = 0, length = 8)
		public int firstByte() {
			return super.getUByte(0); /* 8bits unsigned */
		}

		/**
		 * First byte description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String firstByteDescription() {
			return "hop set";
		}

		/**
		 * Second byte.
		 * 
		 * @return the int
		 */
		@Field(format = "%x", offset = 8, length = 8)
		public int secondByte() {
			return super.getUByte(1); /* 8bits unsigned */
		}

		/**
		 * Second byte description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String secondByteDescription() {
			return "hop pattern";
		}

		/* TODO: DataField_FHSS test, description */
	}

	/**
	 * The Class DataField_DBM_ANTENNA_SIGNAL.
	 */
	@Header(id = 6)
	public static class DataField_DBM_ANTENNA_SIGNAL
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 8;
		}

		/**
		 * RF signal power at the antenna, decibel difference from one milliwatt.
		 */
		@Field(format = "%d", offset = 0, length = 8)
		public int DBM_ANTENNA_SIGNAL() {
			return super.getByte(0); /* 8bits signed */
		}

		/**
		 * DB m_ antenn a_ signal description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String DBM_ANTENNA_SIGNALDescription() {
			return DBM_ANTENNA_SIGNAL() + " dBm";
		}
	}

	/**
	 * The Class DataField_DBM_ANTENNA_NOISE.
	 */
	@Header(id = 7)
	public static class DataField_DBM_ANTENNA_NOISE
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 8;
		}

		/**
		 * RF noise power at the antenna, decibel difference from one milliwatt.
		 */
		@Field(format = "%d", offset = 0, length = 8)
		public int DBM_ANTENNA_NOISE() {
			return super.getByte(0); /* 8bits signed */
		}

		/**
		 * DB m_ antenn a_ noise description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String DBM_ANTENNA_NOISEDescription() {
			return DBM_ANTENNA_NOISE() + " dBm";
		}

		/* TODO: DataField_DBM_ANTENNA_NOISE test */
	}

	/**
	 * The Class DataField_LOCK_QUALITY.
	 */
	@Header(id = 8)
	public static class DataField_LOCK_QUALITY
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 16;
		}

		/**
		 * Quality of Barker code lock. Unitless. Monotonically nondecreasing with
		 * "better" lock strength. Called "Signal Quality" in datasheets. (Is there
		 * a standard way to measure this?)
		 */
		@Field(format = "%d", offset = 0, length = 16)
		public int LOCK_QUALITY() {
			return super.getUShort(0); /* 16bits unsigned */
		}

		/* TODO: DataField_LOCK_QUALITY test, description */
	}

	/**
	 * The Class DataField_TX_ATTENUATION.
	 */
	@Header(id = 9)
	public static class DataField_TX_ATTENUATION
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 16;
		}

		/**
		 * Transmit power expressed as unitless distance from max power set at
		 * factory calibration. 0 is max power. Monotonically nondecreasing with
		 * lower power levels.
		 */
		@Field(format = "%d", offset = 0, length = 16)
		public int TX_ATTENUATION() {
			return super.getUShort(0); /* 16bits unsigned */
		}

		/* TODO: DataField_TX_ATTENUATION test, description */
	}

	/**
	 * The Class DataField_DB_TX_ATTENUATION.
	 */
	@Header(id = 10)
	public static class DataField_DB_TX_ATTENUATION
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 16;
		}

		/**
		 * Transmit power expressed as decibel distance from max power set at
		 * factory calibration. 0 is max power. Monotonically nondecreasing with
		 * lower power levels.
		 */
		@Field(format = "%d", offset = 0, length = 16)
		public int DB_TX_ATTENUATION() {
			return super.getUShort(0); /* 16bits unsigned */
		}

		/**
		 * D b_ t x_ attenuation description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String DB_TX_ATTENUATIONDescription() {
			return DB_TX_ATTENUATION() + " dB";
		}

		/* TODO: DataField_DB_TX_ATTENUATION test, description */
	}

	/**
	 * The Class DataField_DBM_TX_POWER.
	 */
	@Header(id = 11)
	public static class DataField_DBM_TX_POWER
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 8;
		}

		/**
		 * Transmit power expressed as dBm (decibels from a 1 milliwatt reference).
		 * This is the absolute power level measured at the antenna port.
		 */
		@Field(format = "%d", offset = 0, length = 8)
		public int DBM_TX_POWER() {
			return super.getByte(0); /* 8bits signed */
		}

		/**
		 * DB m_ t x_ power description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String DBM_TX_POWERDescription() {
			return DBM_TX_POWER() + " dBm";
		}

		/* TODO: DataField_DBM_TX_POWER test, description */
	}

	/**
	 * The Class DataField_ANTENNA.
	 */
	@Header(id = 12)
	public static class DataField_ANTENNA
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 8;
		}

		/**
		 * Unitless indication of the Rx/Tx antenna for this packet. The first
		 * antenna is antenna 0.
		 */
		@Field(format = "%d", offset = 0, length = 8)
		public int ANTENNA() {
			return super.getUByte(0); /* 8bits unsigned */
		}

		/* TODO: DataField_ANTENNA test, description */
	}

	/**
	 * The Class DataField_DB_ANTENNA_SIGNAL.
	 */
	@Header(id = 13)
	public static class DataField_DB_ANTENNA_SIGNAL
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 8;
		}

		/**
		 * RF signal power at the antenna, decibel difference from an arbitrary,
		 * fixed reference.
		 */
		@Field(format = "%d", offset = 0, length = 8)
		public int DB_ANTENNA_SIGNAL() {
			return super.getUByte(0); /* 8bits unsigned */
		}

		/**
		 * D b_ antenn a_ signal description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String DB_ANTENNA_SIGNALDescription() {
			return DB_ANTENNA_SIGNAL() + " dB";
		}

		/* TODO: DataField_DB_ANTENNA_SIGNAL test, description */
	}

	/**
	 * The Class DataField_DB_ANTENNA_NOISE.
	 */
	@Header(id = 14)
	public static class DataField_DB_ANTENNA_NOISE
	    extends DataField {

		/**
		 * Gets the header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the header length
		 */
		@HeaderLength
		public static int getHeaderLength(JBuffer buffer, int offset) {
			return 8;
		}

		/**
		 * RF noise power at the antenna, decibel difference from an arbitrary,
		 * fixed reference.
		 */
		@Field(format = "%d", offset = 0, length = 8)
		public int DB_ANTENNA_NOISE() {
			return super.getUByte(0); /* 8bits unsigned */
		}

		/**
		 * D b_ antenn a_ noise description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String DB_ANTENNA_NOISEDescription() {
			return DB_ANTENNA_NOISE() + " dB";
		}

		/* TODO: DataField_DB_ANTENNA_NOISE test, description */
	}

	/** The Constant BYTE_ORDER. */
	public static final ByteOrder BYTE_ORDER = ByteOrder.LITTLE_ENDIAN;

	/** The Constant PRESESENT_MASK_TSFT. */
	public static final int PRESESENT_MASK_TSFT = 0x00000001;

	/** The Constant PRESENT_MASK_FLAGS. */
	public static final int PRESENT_MASK_FLAGS = 0x00000002;

	/** The Constant PRESENT_MASK_RATE. */
	public static final int PRESENT_MASK_RATE = 0x00000004;

	/** The Constant PRESENT_MASK_CHANNEL. */
	public static final int PRESENT_MASK_CHANNEL = 0x00000008;

	/** The Constant PRESENT_MASK_FHSS. */
	public static final int PRESENT_MASK_FHSS = 0x00000010;

	/** The Constant PRESENT_MASK_DBM_ANTENNA_SIGNAL. */
	public static final int PRESENT_MASK_DBM_ANTENNA_SIGNAL = 0x00000020;

	/** The Constant PRESENT_MASK_DBM_ANTENNA_NOISE. */
	public static final int PRESENT_MASK_DBM_ANTENNA_NOISE = 0x00000040;

	/** The Constant PRESENT_MASK_LOCK_QUALITY. */
	public static final int PRESENT_MASK_LOCK_QUALITY = 0x00000080;

	/** The Constant PRESENT_MASK_TX_ATTENUATION. */
	public static final int PRESENT_MASK_TX_ATTENUATION = 0x00000100;

	/** The Constant PRESENT_MASK_DB_TX_ATTENUATION. */
	public static final int PRESENT_MASK_DB_TX_ATTENUATION = 0x00000200;

	/** The Constant PRESENT_MASK_DBM_TX_POWER. */
	public static final int PRESENT_MASK_DBM_TX_POWER = 0x00000400;

	/** The Constant PRESENT_MASK_ANTENNA. */
	public static final int PRESENT_MASK_ANTENNA = 0x00000800;

	/** The Constant PRESENT_MASK_DB_ANTENNA_SIGNAL. */
	public static final int PRESENT_MASK_DB_ANTENNA_SIGNAL = 0x00001000;

	/** The Constant PRESENT_MASK_DB_ANTENNA_NOISE. */
	public static final int PRESENT_MASK_DB_ANTENNA_NOISE = 0x00002000;

	/** The Constant PRESENT_MASK_EXT. */
	public static final int PRESENT_MASK_EXT = 0x80000000;

	/**
	 * The Enum IEEE80211_RADIOTAP_DATAFIELD_ID.
	 */
	public enum IEEE80211_RADIOTAP_DATAFIELD_ID {
		
		/** The N o_ field. */
		NO_FIELD,
		
		/** The TSFT. */
		TSFT,
		
		/** The FLAGS. */
		FLAGS,
		
		/** The RATE. */
		RATE,
		
		/** The CHANNEL. */
		CHANNEL,

	}

	/**
	 * The Enum IEEE80211_RADIOTAP_FIELDS.
	 */
	public enum IEEE80211_RADIOTAP_FIELDS {
		
		/** The TSFT. */
		TSFT(PRESESENT_MASK_TSFT, 0x88),
		
		/** The FLAGS. */
		FLAGS(PRESENT_MASK_FLAGS, 0x11),
		
		/** The RATE. */
		RATE(PRESENT_MASK_RATE, 0x11),
		
		/** The CHANNEL. */
		CHANNEL(PRESENT_MASK_CHANNEL, 0x24),
		
		/** The FHSS. */
		FHSS(PRESENT_MASK_FHSS, 0x22),
		
		/** The DB m_ antenn a_ signal. */
		DBM_ANTENNA_SIGNAL(PRESENT_MASK_DBM_ANTENNA_SIGNAL, 0x11),
		
		/** The DB m_ antenn a_ noise. */
		DBM_ANTENNA_NOISE(PRESENT_MASK_DBM_ANTENNA_NOISE, 0x11),
		
		/** The LOC k_ quality. */
		LOCK_QUALITY(PRESENT_MASK_LOCK_QUALITY, 0x22),
		
		/** The T x_ attenuation. */
		TX_ATTENUATION(PRESENT_MASK_TX_ATTENUATION, 0x22),
		
		/** The D b_ t x_ attenuation. */
		DB_TX_ATTENUATION(PRESENT_MASK_DB_TX_ATTENUATION, 0x22),
		
		/** The DB m_ t x_ power. */
		DBM_TX_POWER(PRESENT_MASK_DBM_TX_POWER, 0x11),
		
		/** The ANTENNA. */
		ANTENNA(PRESENT_MASK_ANTENNA, 0x11),
		
		/** The D b_ antenn a_ signal. */
		DB_ANTENNA_SIGNAL(PRESENT_MASK_DB_ANTENNA_SIGNAL, 0x11),
		
		/** The D b_ antenn a_ noise. */
		DB_ANTENNA_NOISE(PRESENT_MASK_DB_ANTENNA_NOISE, 0x11), ;

		/**
		 * IEEE80211_RADIOTAP_RX_FLAGS = 0x22, IEEE80211_RADIOTAP_TX_FLAGS = 0x22,
		 * IEEE80211_RADIOTAP_RTS_RETRIES = 0x11, IEEE80211_RADIOTAP_DATA_RETRIES =
		 * 0x11, add more here as they are defined in
		 * include/net/ieee80211_radiotap.h TODO: wireshark knows more data fields
		 * [channel+, fcs in header, ...] -- radiotap.org doesn't ???
		 */

		private final int mask;

		/**
		 * upper nybble: content alignment for field offset lower nybble: content
		 * length for field offset
		 */
		private final int size;

		/**
		 * Instantiates a new iEE e80211_ radiota p_ fields.
		 * 
		 * @param mask
		 *          the mask
		 * @param size
		 *          the size
		 */
		private IEEE80211_RADIOTAP_FIELDS(int mask, int size) {
			this.mask = mask;
			this.size = size;
		}

		/**
		 * Gets the iEEE80211_RADIOTAP_RX_FLAGS = 0x22, IEEE80211_RADIOTAP_TX_FLAGS
		 * = 0x22, IEEE80211_RADIOTAP_RTS_RETRIES = 0x11,
		 * IEEE80211_RADIOTAP_DATA_RETRIES = 0x11, add more here as they are defined
		 * in include/net/ieee80211_radiotap.
		 * 
		 * @return the iEEE80211_RADIOTAP_RX_FLAGS = 0x22,
		 *         IEEE80211_RADIOTAP_TX_FLAGS = 0x22,
		 *         IEEE80211_RADIOTAP_RTS_RETRIES = 0x11,
		 *         IEEE80211_RADIOTAP_DATA_RETRIES = 0x11, add more here as they are
		 *         defined in include/net/ieee80211_radiotap
		 */
		public final int getMask() {
			return this.mask;
		}

		/**
		 * Gets the upper nybble: content alignment for field offset lower nybble:
		 * content length for field offset.
		 * 
		 * @return the upper nybble: content alignment for field offset lower
		 *         nybble: content length for field offset
		 */
		public final int getSize() {
			return this.size;
		}

	}

	/**
	 * sent/received during CFP
	 */
	public static final int IEEE80211_RADIOTAP_F_CFP = 0x01;

	/**
	 * sent/received with short preamble
	 */
	public static final int IEEE80211_RADIOTAP_F_SHORTPRE = 0x02;

	/**
	 * sent/received with WEP encryption
	 */
	public static final int IEEE80211_RADIOTAP_F_WEP = 0x04;

	/**
	 * sent/received with fragmentation
	 */
	public static final int IEEE80211_RADIOTAP_F_FRAG = 0x08;

	/**
	 * frame includes FCS
	 */
	public static final int IEEE80211_RADIOTAP_F_FCS = 0x10;

	/**
	 * frame has padding between 802.11 header and payload (to 32-bit boundary)
	 */
	public static final int IEEE80211_RADIOTAP_F_DATAPAD = 0x20;

	/** Turbo channel */
	public static final int IEEE80211_RADIOTAP_CHAN_TURBO = 0x0010;

	/** CCK channel */
	public static final int IEEE80211_RADIOTAP_CHAN_CCK = 0x0020;

	/** OFDM channel */
	public static final int IEEE80211_RADIOTAP_CHAN_OFDM = 0x0040;

	/** 2 GHz spectrum channel. */
	public static final int IEEE80211_RADIOTAP_CHAN_2GHZ = 0x0080;

	/** The Constant IEEE80211_RADIOTAP_CHAN_5GHZ. */
	public static final int IEEE80211_RADIOTAP_CHAN_5GHZ = 0x0100;

	/** The Constant IEEE80211_RADIOTAP_CHAN_PASSIVE. */
	public static final int IEEE80211_RADIOTAP_CHAN_PASSIVE = 0x0200;

	/** The Constant IEEE80211_RADIOTAP_CHAN_DYN. */
	public static final int IEEE80211_RADIOTAP_CHAN_DYN = 0x0400;

	/** The Constant IEEE80211_RADIOTAP_CHAN_GFSK. */
	public static final int IEEE80211_RADIOTAP_CHAN_GFSK = 0x0800;

	/* TODO: Wireshark knows 4 more IEEE80211_RADIOTAP_CHAN flags !! */

	/**
	 * Instantiates a new iEE e802dot11_ radiotap.
	 */
	public IEEE802dot11_RADIOTAP() {
		order(BYTE_ORDER);
	}

	/**
	 * Version.
	 * 
	 * @return the int
	 */
	@Field(offset = 0 * 8, length = 8, format = "%d")
	public int version() {
		return super.getUByte(0); /* 8bits unsigned */
	}

	/**
	 * Pad.
	 * 
	 * @return the int
	 */
	@Field(offset = 1 * 8, length = 8, format = "%d")
	public int pad() {
		return super.getUByte(1); /* 8bits unsigned */
	}

	/**
	 * Len.
	 * 
	 * @return the int
	 */
	@Field(offset = 2 * 8, length = 16, format = "%d")
	public int len() {
		return super.getUShort(2); /* 16bits unsigned */
	}

	/**
	 * Gets the header length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the header length
	 */
	@HeaderLength
	public static int getHeaderLength(JBuffer buffer, int offset) {
		return buffer.getUShort(offset + 2); // len
	}

	/**
	 * Present.
	 * 
	 * @return the int
	 */
	@Field(offset = 4 * 8, length = 32, format = "%x")
	public int present() {
		return super.getInt(4); /* 32bits unsigned */
	}

	/**
	 * Present_ tsft.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 0, length = 1, display = "TSFT")
	public int present_TSFT() {
		return (present() & PRESESENT_MASK_TSFT) >> 0;
	}

	/**
	 * Present_ tsft description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_TSFTDescription() {
		return (present_TSFT() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ flags.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 1, length = 1, display = "Flags")
	public int present_Flags() {
		return (present() & PRESENT_MASK_FLAGS) >> 1;
	}

	/**
	 * Present_ flags description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_FlagsDescription() {
		return (present_Flags() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ rate.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 2, length = 1, display = "Rate")
	public int present_Rate() {
		return (present() & PRESENT_MASK_RATE) >> 2;
	}

	/**
	 * Present_ rate description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_RateDescription() {
		return (present_Rate() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ channel.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 3, length = 1, display = "Channel")
	public int present_Channel() {
		return (present() & PRESENT_MASK_CHANNEL) >> 3;
	}

	/**
	 * Present_ channel description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_ChannelDescription() {
		return (present_Channel() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ fhss.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 4, length = 1, display = "FHSS")
	public int present_FHSS() {
		return (present() & PRESENT_MASK_FHSS) >> 4;
	}

	/**
	 * Present_ fhss description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_FHSSDescription() {
		return (present_FHSS() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ antenna signal.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 5, length = 1, display = "Antenna Signal")
	public int present_AntennaSignal() {
		return (present() & PRESENT_MASK_DBM_ANTENNA_SIGNAL) >> 5;
	}

	/**
	 * Present_ antenna signal description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_AntennaSignalDescription() {
		return (present_AntennaSignal() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ antenna noise.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 6, length = 1, display = "Antenna Noise")
	public int present_AntennaNoise() {
		return (present() & PRESENT_MASK_DBM_ANTENNA_NOISE) >> 6;
	}

	/**
	 * Present_ antenna noise description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_AntennaNoiseDescription() {
		return (present_AntennaNoise() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ lock quality.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 7, length = 1, display = "Lock Quality")
	public int present_LockQuality() {
		return (present() & PRESENT_MASK_LOCK_QUALITY) >> 7;
	}

	/**
	 * Present_ lock quality description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_LockQualityDescription() {
		return (present_LockQuality() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ tx attenuation.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 8, length = 1, display = "TX Attenuation")
	public int present_TXAttenuation() {
		return (present() & PRESENT_MASK_TX_ATTENUATION) >> 8;
	}

	/**
	 * Present_ tx attenuation description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_TXAttenuationDescription() {
		return (present_TXAttenuation() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ dbtx attenuation.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 9, length = 1, display = "dB TX Attenuation")
	public int present_DBTXAttenuation() {
		return (present() & PRESENT_MASK_DB_TX_ATTENUATION) >> 9;
	}

	/**
	 * Present_ dbtx attenuation description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_DBTXAttenuationDescription() {
		return (present_DBTXAttenuation() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ dbmtx power.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 10, length = 1, display = "dBm TX Power")
	public int present_DBMTXPower() {
		return (present() & PRESENT_MASK_DBM_TX_POWER) >> 10;
	}

	/**
	 * Present_ dbmtx power description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_DBMTXPowerDescription() {
		return (present_DBMTXPower() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ antenna.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 11, length = 1, display = "Antenna")
	public int present_Antenna() {
		return (present() & PRESENT_MASK_ANTENNA) >> 11;
	}

	/**
	 * Present_ antenna description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_AntennaDescription() {
		return (present_Antenna() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ db antenna signal.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 12, length = 1, display = "dB Antenna Signal")
	public int present_DBAntennaSignal() {
		return (present() & PRESENT_MASK_DB_ANTENNA_SIGNAL) >> 12;
	}

	/**
	 * Present_ db antenna signal description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_DBAntennaSignalDescription() {
		return (present_DBAntennaSignal() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ db antenna noise.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 13, length = 1, display = "dB Antenna Noise")
	public int present_DBAntennaNoise() {
		return (present() & PRESENT_MASK_DB_ANTENNA_NOISE) >> 13;
	}

	/**
	 * Present_ db antenna noise description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_DBAntennaNoiseDescription() {
		return (present_DBAntennaNoise() > 0) ? "set" : "not set";
	}

	/**
	 * Present_ ext.
	 * 
	 * @return the int
	 */
	@Field(parent = "present", offset = 31, length = 1, display = "Ext")
	public int present_Ext() {
		return (present() & PRESENT_MASK_EXT) >> 31;
	}

	/**
	 * Present_ ext description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String present_ExtDescription() {
		return (present_Ext() > 0) ? "set" : "not set";
	}

	/**
	 * Scanner.
	 * 
	 * @param scan
	 *          the scan
	 */
	@Scanner
	public static void scanner(JScan scan) {

		/*
		 * Packet extends JBuffer. The packet object is the one that is already
		 * created for the scanner in the Pcap.loop call and is already peered. This
		 * is better approach than getting the buffer with: JBuffer b = new
		 * JBuffer(Type.POINTER); scan.scan_buf(b);
		 */
		JPacket packet = scan.scan_packet();

		/*
		 * Thats good
		 */
		int offset = scan.scan_offset();

		/*
		 * Should put this outside the method body as a private field. Do it once
		 * everytime the header is created.
		 */
		@SuppressWarnings("unused")
		int id = JRegistry.lookupId(IEEE802dot11_RADIOTAP.class);

		// JRegistry.lookupId(IEEE802dot11.class);

		/*
		 * Good. Exactly why @HeaderLength methods are static
		 */
		scan.scan_length(getHeaderLength(packet, offset));

		/*
		 * Now here the scan_id is already set, otherwise this @Scanner method would
		 * not be getting called. What you want to set is the next_id which is the
		 * ID of the next header or leave next at PAYLOAD_ID which will force the
		 * JHeaderScanner that called this @Scanner method to also check the reverse
		 * bindings. If you set the next_id to anything other than PAYLOAD or
		 * JScan.END_OF_HEADERS_ID, that id will be used as the next protocol in the
		 * header (another iteration of the loop will make it the current id)
		 */
		// scan.scan_id(id);
		// scan.scan_next_id(next_id);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {
		optionsBitmap = 0;

		int offset = 8;
		int pad = 0;

		int id = 0;
		int is_present = 0;
		int present_bitmap = present();
		int field_length = 0;

		for (IEEE80211_RADIOTAP_FIELDS field : IEEE80211_RADIOTAP_FIELDS.values()) {

			id = field.ordinal() + 1;
			pad = offset & ((field.size >> 4) - 1);
			is_present = (present_bitmap & field.mask) >> (id - 1);

			optionsBitmap |= (is_present << id);

			if (is_present > 0) {
				if (pad > 0) {
					offset += (field.size >> 4) - pad;
				}

				field_length = field.size & 0x0f;

				optionsOffsets[id] = offset;
				optionsLength[id] = field_length;

				offset += field_length;
			}

			System.out
			    .printf(
			        "id=%d name=%s is_present=%d present_bitmap=0x%X optionsBitmap=0x%X pad=%d offset of next field=%d length=%d  \n",
			        id, field.name(), is_present, present_bitmap, optionsBitmap, pad,
			        offset, optionsLength[id]);
		}

		/* TODO: hashcode? */
	}

}
