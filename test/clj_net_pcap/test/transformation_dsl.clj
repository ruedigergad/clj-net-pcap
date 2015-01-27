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
    :doc "Tests for transforming data via a DSL"}  
  clj-net-pcap.test.transformation-dsl
  (:use clojure.test
        clj-net-pcap.core
        clj-net-pcap.pcap-data
        clj-assorted-utils.util)
  (:import (clj_net_pcap PacketHeaderDataBeanIpv4UdpOnly)))

(deftest test-extract-udp-maps-from-pcap-file-ipv4-udp-only-reference
  (let [my-maps (extract-data-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap" pcap-packet-to-map-ipv4-udp-only)]
    (is (= 2 (count my-maps)))
    (is (= {"ipVer" 4, "ipDst" "192.168.0.1", 
            "ipSrc" "192.168.0.51", "ethDst" "00:24:FE:B1:8F:DC", 
            "ipId" 20831, "ipTtl" 64, "ipChecksum" 26570,
            "ethSrc" "74:DE:2B:08:78:09", "ts" 1385804494276477000, "len" 77,
            "udpSrc" 34904, "udpDst" 53}
           (first my-maps)))))

(deftest test-extract-udp-beans-from-pcap-file-ipv4-udp-only-reference
  (let [my-beans (extract-data-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap" pcap-packet-to-bean-ipv4-udp-only)
        expected (doto (PacketHeaderDataBeanIpv4UdpOnly.)
                   (.setTs 1385804494276477000) (.setLen 77)
                   (.setEthDst "00:24:FE:B1:8F:DC") (.setEthSrc "74:DE:2B:08:78:09")
                   (.setIpDst "192.168.0.1") (.setIpSrc "192.168.0.51")
                   (.setIpId 20831) (.setIpTtl 64) (.setIpChecksum 26570)
                   (.setIpVer 4) (.setUdpSrc 34904) (.setUdpDst 53))]
    (is (= 2 (count my-beans)))
    (is (= expected
           (first my-beans)))))

(deftest test-extract-data-from-byte-array-to-map-ipv4-udp-only
  (let [expected-map {"len" 0, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                      "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3,
                      "ipTtl" 7, "ipSrc" "1.2.3.4", "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "ts" 0}
        pkt-raw-vec [0 0 0 0   0 0 0 0   0 0 0 0   0 0 0 0                 ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extracted-map (packet-byte-array-extract-map-ipv4-udp pkt-ba)]
    (is (= expected-map extracted-map))))

