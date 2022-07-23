/*
 * Copyright (c) 2020 Sly Technologies Inc.
 */
/**
 * @author mark
 *
 */
module org.jnetpcap {
	exports org.jnetpcap;
	exports org.jnetpcap.util.checksum;
	exports org.jnetpcap.extension;
	exports org.jnetpcap.util.config;
	exports org.jnetpcap.util;
	exports org.jnetpcap.winpcap;
	exports org.jnetpcap.protocol;
	exports org.jnetpcap.protocol.sigtran;
	exports org.jnetpcap.protocol.vpn;
	exports org.jnetpcap.protocol.voip;
	exports org.jnetpcap.packet.annotate;
	exports org.jnetpcap.protocol.tcpip;
	exports org.jnetpcap.util.resolver;
	exports org.jnetpcap.packet;
	exports org.jnetpcap.packet.format;
	exports org.jnetpcap.protocol.tcpip.radius;
	exports org.jnetpcap.protocol.wan;
	exports org.jnetpcap.protocol.lan;
	exports org.jnetpcap.packet.structure;
	exports org.jnetpcap.nio;
	exports org.jnetpcap.protocol.application;
	exports org.jnetpcap.protocol.network;

	requires java.desktop;
	requires java.logging;
	requires java.sql;
}