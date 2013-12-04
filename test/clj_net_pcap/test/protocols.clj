;;;
;;; Copyright (C) 2012 Ruediger Gad
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
    :doc "Tests for protocol parsing"}  
  clj-net-pcap.test.protocols
  (:use clojure.test
        clj-net-pcap.core
        clj-assorted-utils.util)
  (:import (clj_net_pcap PacketHeaderDataBean)))

(deftest test-extract-tcp-maps-from-pcap-file
  (let [my-maps (extract-maps-from-pcap-file "test/clj_net_pcap/test/data/tcp-syn-ack.pcap")]
    (is (= 1 (count my-maps)))
    (is (= {"ipVer" 4, "ipDst" "192.168.0.51", 
            "ipId" 0, "ipTtl" 48, "ipChecksum" 844,
            "ipSrc" "209.132.181.16", "ethDst" "74:DE:2B:08:78:09", 
            "ethSrc" "00:24:FE:B1:8F:DC", "ts" 1385804488699025000, "len" 74,
            "tcpSrc" 80, "tcpDst" 42229, "tcpFlags" 18,
            "tcpAck" 2657863316, "tcpSeq" 1606436657}
           (first my-maps)))))

(deftest test-extract-tcp-beans-from-pcap-file
  (let [my-beans (extract-beans-from-pcap-file "test/clj_net_pcap/test/data/tcp-syn-ack.pcap")
        expected (doto (PacketHeaderDataBean.)
                   (.setTs 1385804488699025000) (.setLen 74)
                   (.setEthDst "74:DE:2B:08:78:09") (.setEthSrc "00:24:FE:B1:8F:DC")
                   (.setIpDst "192.168.0.51") (.setIpSrc "209.132.181.16")
                   (.setIpId 0) (.setIpTtl 48) (.setIpChecksum 844)
                   (.setIpVer 4) (.setTcpSrc 80) (.setTcpDst 42229) (.setTcpFlags 18)
                   (.setTcpAck 2657863316) (.setTcpSeq 1606436657))]
    (is (= 1 (count my-beans)))
    (is (= expected
           (first my-beans)))))

(deftest test-extract-udp-maps-from-pcap-file
  (let [my-maps (extract-maps-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap")]
    (is (= 2 (count my-maps)))
    (is (= {"ipVer" 4, "ipDst" "192.168.0.1", 
            "ipSrc" "192.168.0.51", "ethDst" "00:24:FE:B1:8F:DC", 
            "ipId" 20831, "ipTtl" 64, "ipChecksum" 26570,
            "ethSrc" "74:DE:2B:08:78:09", "ts" 1385804494276477000, "len" 77,
            "udpSrc" 34904, "udpDst" 53}
           (first my-maps)))))

(deftest test-extract-udp-beans-from-pcap-file
  (let [my-beans (extract-beans-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap")
        expected (doto (PacketHeaderDataBean.)
                   (.setTs 1385804494276477000) (.setLen 77)
                   (.setEthDst "00:24:FE:B1:8F:DC") (.setEthSrc "74:DE:2B:08:78:09")
                   (.setIpDst "192.168.0.1") (.setIpSrc "192.168.0.51")
                   (.setIpId 20831) (.setIpTtl 64) (.setIpChecksum 26570)
                   (.setIpVer 4) (.setUdpSrc 34904) (.setUdpDst 53))]
    (is (= 2 (count my-beans)))
    (is (= expected
           (first my-beans)))))
