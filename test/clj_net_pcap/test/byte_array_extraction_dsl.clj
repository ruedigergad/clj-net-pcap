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
    :doc "Tests for extracting data from byte arrays via a DSL."}
  clj-net-pcap.test.byte-array-extraction-dsl
  (:use clojure.test
        clj-net-pcap.byte-array-extraction-dsl
        clj-net-pcap.core
        clj-net-pcap.pcap-data
        clj-assorted-utils.util)
  (:import (clj_net_pcap PacketHeaderDataBeanIpv4UdpOnly)))

(deftest test-extract-data-from-byte-array-to-map-ipv4-udp-only
  (let [expected-map {"len" 77, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                      "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3,
                      "ipTtl" 7, "ipSrc" "1.2.3.4", "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "ts" 1422366459969231000}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extracted-map (packet-byte-array-extract-map-ipv4-udp-be pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest simple-hardcoded-offsets-dsl-test
  (let [expected-map {"udpSrc" 2048, "udpDst" 4096}
        dsl-expression [{:offset 50 :transformation "int16" :name "udpSrc"}
                        {:offset 52 :transformation "int16" :name "udpDst"}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba)]
    (is (= expected-map extracted-map))))

(deftest simple-packet-offsets-name-dsl-test
  (let [expected-map {"udpSrc" 2048, "udpDst" 4096}
        dsl-expression [{:offset "udp-src" :transformation "int16" :name "udpSrc"}
                        {:offset "udp-dst" :transformation "int16" :name "udpDst"}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba)]
    (is (= expected-map extracted-map))))

