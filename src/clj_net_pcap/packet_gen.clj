;;;
;;; Copyright (C) 2015-2022 Ruediger Gad
;;;
;;; This file is part of clj-net-pcap.
;;; clj-net-pcap is licensed under the terms of either
;;; - the GNU Lesser General Public License (LGPL) version 3 or later
;;;   http://www.gnu.org/licenses/lgpl-3.0.html
;;; or, at your option,
;;; - the Eclipse Public License (EPL) 1.0.
;;;   http://opensource.org/licenses/eclipse-1.0.php
;;;
;;; By contributing to clj-net-pcap, you agree that your contribution will be licensed under both licenses
;;; and that users of clj-net-pcap can chose any of these licenses.
;;;

(ns 
  ^{:author "Ruediger Gad",
    :doc "The packet-gen namespace contains functionality for generating and sending packets."}
  clj-net-pcap.packet-gen
  (:require
    (clj-assorted-utils [util :as utils]))
  (:import (clj_net_pcap ByteArrayHelper)
           (java.util Map)
           (org.jnetpcap.packet JMemoryPacket)
           (org.jnetpcap.protocol JProtocol)
           (org.jnetpcap.protocol.lan Ethernet Ethernet$EthernetType)
           (org.jnetpcap.protocol.network Icmp Icmp$EchoRequest Ip4)
           (org.jnetpcap.protocol.tcpip Udp)))

(def def-hdr-len-eth 14)
(def def-hdr-len-ip4 20)
(def def-hdr-len-icmp 16)
(def def-hdr-len-udp 8)

(def ip-type-icmp 1)
(def ip-type-udp 17)

(defn get-data-length
  "Calculate the length of the provided data.
   If counted? is true for data, the count is returned.
   If data is a String, the String length is returned.
   For unknown types, 0 is returned."
  [data]
  (cond
    (counted? data) (count data)
    (= String (type data)) (.length ^String data)
    :else 0))

(defn get-data-val
  "Get the byte-array representation of the supplied data.
   If counted? is true for data, all elements will be coerced to byte.
   If data is a String, the byte-array representation of the String is returned.
   Otherwise, a zero length byte-array is returned."
  [data]
  (cond
    (counted? data) (byte-array (map byte data))
    (= String (type data)) (.getBytes ^String data)
    :else (byte-array 0)))

(defn generate-packet-data
  "Generate a byte-array representation of the packet according to the given packet description map."
  [^Map pkt-desc-map]
  (let [len (if (.containsKey pkt-desc-map "len")
              (.get pkt-desc-map "len")
              (let [eth-hdr-len def-hdr-len-eth
                    ip-hdr-len (condp = (utils/get-with-default pkt-desc-map "ipVer" 0)
                                 4 def-hdr-len-ip4
                                 0)
                    ip-payload-hdr-len (condp = (utils/get-with-default pkt-desc-map "ipType" 0)
                                         ip-type-icmp def-hdr-len-icmp
                                         ip-type-udp def-hdr-len-udp
                                         0)
                    payload-len (get-data-length (utils/get-with-default pkt-desc-map "data" nil))]
                (+ eth-hdr-len ip-hdr-len ip-payload-hdr-len payload-len)))
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
            (.id (int (utils/get-with-default pkt-desc-map "ipId" 0)))
            (.flags (int (utils/get-with-default pkt-desc-map "ipFlags" 2)))
            (.offset 0)
            (.ttl (int (utils/get-with-default pkt-desc-map "ipTtl" 16)))
            (.type (int (utils/get-with-default pkt-desc-map "ipType" 0)))
            (.source (ByteArrayHelper/ipv4StringToByteArrayUnchecked (.get pkt-desc-map "ipSrc")))
            (.destination (ByteArrayHelper/ipv4StringToByteArrayUnchecked (.get pkt-desc-map "ipDst"))))
          (if (.containsKey pkt-desc-map "ipChecksum")
            (.checksum ip4 (.get pkt-desc-map "ipChecksum"))
            (.checksum ip4 (.calculateChecksum ip4))))
        (println "Generating IPv6 is not yet implemented."))
      (.scan jpkt JProtocol/ETHERNET_ID)
      (condp = (utils/get-with-default pkt-desc-map "ipType" 0)
        ip-type-icmp (let [^Icmp icmp (.getHeader jpkt (Icmp.))
                           icmpType (int (utils/get-with-default pkt-desc-map "icmpType" 0))]
                       (doto icmp
                         (.type icmpType)
                         (.code (int (utils/get-with-default pkt-desc-map "icmpCode" 0)))
                         (.decode))
                       (condp = icmpType
                         8 (let [icmp-echo-req (.getSubHeader icmp (Icmp$EchoRequest.))]
                             (doto icmp-echo-req
                               (.id (utils/get-with-default pkt-desc-map "icmpId" 0))
                               (.sequence (utils/get-with-default pkt-desc-map "icmpSeqNo" 0)))
                             (when (.containsKey pkt-desc-map "data")
                               (let [data (utils/get-with-default pkt-desc-map "data" "")
                                     data-val (get-data-val data)]
                                 (.setByteArray jpkt (+ (.getHeaderLength eth) 20 8 (.getHeaderLength icmp)) data-val))))
                         nil)
                       (.recalculateChecksum icmp))
        ip-type-udp (let [^Udp udp (.getHeader jpkt (Udp.))
                          data (utils/get-with-default pkt-desc-map "data" nil)]
                      (doto udp
                        (.source (int (utils/get-with-default pkt-desc-map "udpSrc" 2048)))
                        (.destination (int (utils/get-with-default pkt-desc-map "udpDst" 2048)))
                        (.length (get-data-length data)))
                      (when (not (nil? data))
                        (.setByteArray jpkt (+ (.getHeaderLength eth) def-hdr-len-ip4 (.getHeaderLength udp)) (get-data-val data)))
                      (.recalculateChecksum udp))
        nil))
    (.getByteArray jpkt 0 ba)))
