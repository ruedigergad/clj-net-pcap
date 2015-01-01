;;;
;;; Copyright (C) 2015 Ruediger Gad
;;;
;;; This file is part of clj-net-pcap.
;;;
;;; clj-net-pcap is free software: you can redistribute it and/or modify
;;; it under the terms of the GNU Lesser General Public License (LGPL) as
;;; published by the Free Software Foundation, either version 3 of the License,
;;; or (at your option any later version.
;;;
;;; clj-net-pcap is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU Lesser General Public License (LGPL) for more details.
;;;
;;; You should have received a copy of the GNU Lesser General Public License (LGPL)
;;; along with clj-net-pcap.  If not, see <http://www.gnu.org/licenses/>.
;;;

(ns 
  ^{:author "Ruediger Gad",
    :doc "The packet-gen namespace contains functionality for generating and sending packets."}
  clj-net-pcap.packet-gen
  (:use clj-net-pcap.pcap
        clj-assorted-utils.util)
  (:import (clj_net_pcap ByteArrayHelper)
           (java.nio BufferUnderflowException ByteBuffer)
           (java.util Map)
           (java.util.concurrent ArrayBlockingQueue)
           (org.jnetpcap Pcap PcapDLT PcapHeader)
           (org.jnetpcap.nio JBuffer JMemory JMemory$Type)
           (org.jnetpcap.packet JPacket JMemoryPacket)
           (org.jnetpcap.protocol JProtocol)
           (org.jnetpcap.protocol.lan Ethernet Ethernet$EthernetType)
           (org.jnetpcap.protocol.network Icmp Icmp$Echo Icmp$EchoReply Icmp$EchoRequest Icmp$IcmpType Ip4 Ip4$Flag Ip6)
           (org.jnetpcap.protocol.tcpip Udp)))

(defn generate-packet-data
  [^Map pkt-desc-map]
  (let [len (.get pkt-desc-map "len")
        ba (byte-array len)
        jpkt (JMemoryPacket. JProtocol/ETHERNET_ID ba)
        ^Ethernet eth (.getHeader jpkt (Ethernet.))]
    (doto eth
      (.destination #^bytes (ByteArrayHelper/ethMacStringToByteArrayUnchecked (.get pkt-desc-map "ethDst")))
      (.source #^bytes (ByteArrayHelper/ethMacStringToByteArrayUnchecked (.get pkt-desc-map "ethSrc"))))
    (when-let [ipVer (.get pkt-desc-map "ipVer")]
      (if (= ipVer 4)
        (let [_ (.type eth (.getId Ethernet$EthernetType/IP4))
              _ (doto jpkt 
                  (.setByte (.getHeaderLength eth) 69)
                  (.scan JProtocol/ETHERNET_ID))
              ^Ip4 ip4 (.getHeader jpkt (Ip4.))]
          (doto ip4
            (.version ipVer)
            (.hlen 5)
            (.tos 0)
            (.length (- len (.getHeaderLength eth)))
            (.id (int (get-with-default pkt-desc-map "ipId" 0)))
            (.flags (int (get-with-default pkt-desc-map "ipFlags" 2)))
            (.offset 0)
            (.ttl (int (get-with-default pkt-desc-map "ipTtl" 16)))
            (.type (int (get-with-default pkt-desc-map "ipType" 0)))
            (.source (ByteArrayHelper/ipv4StringToByteArrayUnchecked (.get pkt-desc-map "ipSrc")))
            (.destination (ByteArrayHelper/ipv4StringToByteArrayUnchecked (.get pkt-desc-map "ipDst"))))
          (if (.containsKey pkt-desc-map "ipChecksum")
            (.checksum ip4 (.get pkt-desc-map "ipChecksum"))
            (.checksum ip4 (.calculateChecksum ip4))))
        (println "Generating IPv6 is not yet implemented."))
      (.scan jpkt JProtocol/ETHERNET_ID)
      (condp = (get-with-default pkt-desc-map "ipType" 0)
        1 (let [^Icmp icmp (.getHeader jpkt (Icmp.))
                icmpType (int (get-with-default pkt-desc-map "icmpType" 0))]
            (doto icmp
              (.type icmpType)
              (.code (int (get-with-default pkt-desc-map "icmpCode" 0)))
              (.decode))
            (condp = icmpType
              8 (let [icmp-echo-req (.getSubHeader icmp (Icmp$EchoRequest.))]
                  (doto icmp-echo-req
                    (.id (get-with-default pkt-desc-map "icmpId" 0))
                    (.sequence (get-with-default pkt-desc-map "icmpSeqNo" 0)))
                  (when-let [data (.get pkt-desc-map "data")]
                    (.setByteArray jpkt (+ (.getHeaderLength eth) 20 8 (.getHeaderLength icmp)) (.getBytes data))))
              nil)
            (.recalculateChecksum icmp))
        17 (let [^Udp udp (.getHeader jpkt (Udp.))
                 ^String data (get-with-default pkt-desc-map "data" "")]
             (doto udp
               (.source (int (get-with-default pkt-desc-map "udpSrc" 2048)))
               (.destination (int (get-with-default pkt-desc-map "udpDst" 2048)))
               (.length (.length data)))
             (if (> (.length data) 0)
               (.setByteArray jpkt (+ (.getHeaderLength eth) 20 (.getHeaderLength udp)) (.getBytes data)))
             (.recalculateChecksum udp))
        nil))
    (.getByteArray jpkt 0 ba)))

