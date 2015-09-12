;;;
;;; Copyright (C) 2013 Ruediger Gad
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
    :doc "Tests for clj-net-pcap Java interoperability"}
  clj-net-pcap.test.java-interop
  (:use clojure.test
        clj-assorted-utils.util)
  (:import (clj_net_pcap CljNetPcapJavaAdapter PacketHeaderDataBean)))

(def test-file "test/clj_net_pcap/test/data/offline-test.pcap")

(deftest test-java-static-extract-nested-maps-from-pcap-file
  (let [my-map (CljNetPcapJavaAdapter/extractNestedMapsFromPcapFile "test/clj_net_pcap/test/data/icmp-echo-request.pcap")]
    (is (= 1 (count my-map)))
    (is (= {"PcapHeader" {"timestampInNanos" 1365516583196346000, "wirelen" 98},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet", "destination" "E0:CB:4E:E3:38:46", "source" "90:E6:BA:3C:9A:47", "next" 2},
            "NetworkLayer" {
;              "destinationNetmaskBits" 24, "destinationNetwork" "192.168.20.0", "sourceNetwork" "192.168.20.0", "sourceNetmaskBits" 24},
              "ttl" 64, "destination" "173.194.69.94", "index" 1, "ProtocolType" "Ip4", "next" 12, "tos" 0, "type" 1, "source" "192.168.20.126", "id" 0
            }
            "Icmp" {"index" 2, "typeDescription" "echo request", "next" 0}}
            (first my-map)))))

(deftest test-java-static-extract-maps-from-pcap-file
  (let [my-map (CljNetPcapJavaAdapter/extractMapsFromPcapFile "test/clj_net_pcap/test/data/icmp-echo-request.pcap")]
    (is (= 1 (count my-map)))
    (is (= {"ts" 1365516583196346000, "len" 98,
            "ethDst" "E0:CB:4E:E3:38:46", "ethSrc" "90:E6:BA:3C:9A:47",
            "ipDst" "173.194.69.94", "ipSrc" "192.168.20.126", "ipVer" 4,
            "ipId" 0, "ipTtl" 64, "ipChecksum" 29282,
            "icmpType" "echo request", "icmpEchoSeq" 21}
            (first my-map)))))

(deftest test-java-static-extract-beans-from-pcap-file
  (let [my-beans (CljNetPcapJavaAdapter/extractBeansFromPcapFile "test/clj_net_pcap/test/data/icmp-echo-request.pcap")
        expected (doto (PacketHeaderDataBean.)
                   (.setTs 1365516583196346000) (.setLen 98)
                   (.setEthDst "E0:CB:4E:E3:38:46") (.setEthSrc "90:E6:BA:3C:9A:47")
                   (.setIpDst "173.194.69.94") (.setIpSrc "192.168.20.126")
                   (.setIpId 0) (.setIpTtl 64) (.setIpChecksum 29282)
                   (.setIpVer 4) (.setIcmpType "echo request") (.setIcmpEchoSeq 21))]
    (is (= 1 (count my-beans)))
    (is (= expected
           (first my-beans)))))
