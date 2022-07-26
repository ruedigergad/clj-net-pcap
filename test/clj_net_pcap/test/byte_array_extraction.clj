;;;
;;; Copyright (C) 2015 Ruediger Gad
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
    :doc "Tests for extracting data from byte arrays."}  
  clj-net-pcap.test.byte-array-extraction
  (:require
   (clojure [test :as test]))
  (:use
        clj-net-pcap.core
        clj-net-pcap.pcap-data
        clj-assorted-utils.util)
  (:import (clj_net_pcap PacketHeaderDataBeanIpv4UdpOnly)))

(test/deftest test-extract-udp-maps-from-pcap-file-ipv4-udp-only-reference
  (let [my-maps (extract-data-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap" pcap-packet-to-map-ipv4-udp-only)]
    (test/is (= 2 (count my-maps)))
    (test/is (= {"ipVer" 4, "ipDst" "192.168.0.1",
            "ipSrc" "192.168.0.51", "ethDst" "00:24:FE:B1:8F:DC", 
            "ipId" 20831, "ipTtl" 64, "ipChecksum" 26570,
            "ethSrc" "74:DE:2B:08:78:09", "ts" 1385804494276477000, "len" 77,
            "udpSrc" 34904, "udpDst" 53}
           (first my-maps)))))

(test/deftest test-extract-udp-beans-from-pcap-file-ipv4-udp-only-reference
  (let [my-beans (extract-data-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap" pcap-packet-to-bean-ipv4-udp-only)
        expected (doto (PacketHeaderDataBeanIpv4UdpOnly.)
                   (.setTs 1385804494276477000) (.setLen 77)
                   (.setEthDst "00:24:FE:B1:8F:DC") (.setEthSrc "74:DE:2B:08:78:09")
                   (.setIpDst "192.168.0.1") (.setIpSrc "192.168.0.51")
                   (.setIpId 20831) (.setIpTtl 64) (.setIpChecksum 26570)
                   (.setIpVer 4) (.setUdpSrc 34904) (.setUdpDst 53))]
    (test/is (= 2 (count my-beans)))
    (test/is (= expected
           (first my-beans)))))

(test/deftest test-extract-data-from-byte-array-to-map-ipv4-udp-only-be
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
    (test/is (= expected-map extracted-map))))

(test/deftest test-extract-data-from-byte-array-to-map-ipv4-udp-only
  (let [expected-map {"len" 77, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                      "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3,
                      "ipTtl" 7, "ipSrc" "1.2.3.4", "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "ts" 1422366459969231000}
        pkt-raw-vec [84 -57 -106 -5   0 14 -54 15   0 0 0 77   0 0 0 77    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extracted-map (packet-byte-array-extract-map-ipv4-udp pkt-ba 0)]
    (test/is (= expected-map extracted-map))))

(test/deftest test-extract-data-from-byte-array-to-bean-ipv4-udp-only-be
  (let [
        expected (doto (PacketHeaderDataBeanIpv4UdpOnly.)
                   (.setTs 1422366459969231000) (.setLen 77)
                   (.setEthDst "FF:FE:FD:F2:F1:F0") (.setEthSrc "01:02:03:04:05:06")
                   (.setIpDst "252.253.254.255") (.setIpSrc "1.2.3.4")
                   (.setIpId 3) (.setIpTtl 7) (.setIpChecksum 29639)
                   (.setIpVer 4) (.setUdpSrc 2048) (.setUdpDst 4096))
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extracted (packet-byte-array-extract-bean-ipv4-udp-be pkt-ba 0)]
    (test/is (= expected extracted))))

(test/deftest test-extract-data-from-byte-array-to-bean-ipv4-udp-only
  (let [
        expected (doto (PacketHeaderDataBeanIpv4UdpOnly.)
                   (.setTs 1422366459969231000) (.setLen 77)
                   (.setEthDst "FF:FE:FD:F2:F1:F0") (.setEthSrc "01:02:03:04:05:06")
                   (.setIpDst "252.253.254.255") (.setIpSrc "1.2.3.4")
                   (.setIpId 3) (.setIpTtl 7) (.setIpChecksum 29639)
                   (.setIpVer 4) (.setUdpSrc 2048) (.setUdpDst 4096))
        pkt-raw-vec [84 -57 -106 -5   0 14 -54 15   0 0 0 77   0 0 0 77    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extracted (packet-byte-array-extract-bean-ipv4-udp pkt-ba 0)]
    (test/is (= expected extracted))))

