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
           (org.jnetpcap.protocol.network Ip4 Ip4$Flag Ip6)))

(defn generate-packet-data
  [^Map pkt-desc-map]
  (let [len (.get pkt-desc-map "len")
        ba (byte-array len)
        jpkt (JMemoryPacket. JProtocol/ETHERNET_ID ba)
        eth (.getHeader jpkt (Ethernet.))]
    (doto eth
      (.destination (ByteArrayHelper/ethMacStringToByteArrayUnchecked (.get pkt-desc-map "ethDst")))
      (.source (ByteArrayHelper/ethMacStringToByteArrayUnchecked (.get pkt-desc-map "ethSrc"))))
    (when-let [ipVer (.get pkt-desc-map "ipVer")]
      (if (= ipVer 4)
        (let [_ (.type eth (.getId Ethernet$EthernetType/IP4))
              _ (doto jpkt 
                  (.setByte (.getHeaderLength eth) 69)
                  (.scan JProtocol/ETHERNET_ID))
              ^Ip4 ip4 (.getHeader jpkt (Ip4.))]
          (doto ip4
            (.version ipVer)
            (.hlen 20)
            (.tos 0)
            (.length (- len 14))
            (.id (.get pkt-desc-map "ipId"))
            (.flags 2)
            (.offset 0)
            (.ttl (.get pkt-desc-map "ipTtl"))
            (.type 0)
            (.source (ByteArrayHelper/ipv4StringToByteArrayUnchecked (.get pkt-desc-map "ipSrc")))
            (.destination (ByteArrayHelper/ipv4StringToByteArrayUnchecked (.get pkt-desc-map "ipDst"))))
          (if (.containsKey pkt-desc-map "ipChecksum")
            (.checksum ip4 (.get pkt-desc-map "ipChecksum"))
            (.checksum ip4 (.calculateChecksum ip4))))))
    (.getByteArray jpkt 0 ba)))

