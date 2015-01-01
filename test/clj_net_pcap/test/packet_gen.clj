;;;
;;; Copyright (C) 2014, 2015 Ruediger Gad
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
    :doc "Tests for generating packets"}
  clj-net-pcap.test.packet-gen
  (:use clojure.test
        clj-net-pcap.packet-gen
        clj-assorted-utils.util)
  (:import (clj_net_pcap ByteArrayHelper PacketHeaderDataBean)
           (java.util Arrays)
           (org.jnetpcap.packet.format FormatUtils)))

(deftest eth-mac-string-to-byte-array-01_02_03_04_05_06-unchecked-test
  (let [in-str "01:02:03:04:05:06"
        expected (byte-array (map byte [1 2 3 4 5 6]))]
    (is (Arrays/equals expected (ByteArrayHelper/ethMacStringToByteArrayUnchecked in-str)))
    (is (= in-str (FormatUtils/mac expected)))))

(deftest eth-mac-string-to-byte-array-10_11_12_1A_1B_1C-unchecked-test
  (let [in-str "10:11:12:1A:1B:1C"
        expected (byte-array (map byte [16 17 18 26 27 28]))]
    (is (Arrays/equals expected (ByteArrayHelper/ethMacStringToByteArrayUnchecked in-str)))
    (is (= in-str (FormatUtils/mac expected)))))

(deftest eth-mac-string-to-byte-array-7F_80_81_82_83_84-unchecked-test
  (let [in-str "7F:80:81:82:83:84"
        expected (byte-array (map byte [127 -128 -127 -126 -125 -124]))]
    (is (Arrays/equals expected (ByteArrayHelper/ethMacStringToByteArrayUnchecked in-str)))
    (is (= in-str (FormatUtils/mac expected)))))

(deftest eth-mac-string-to-byte-array-FF_FE_FD_F2_F1_F0-unchecked-test
  (let [in-str "FF:FE:FD:F2:F1:F0"
        expected (byte-array (map byte [-1 -2 -3 -14 -15 -16]))]
    (is (Arrays/equals expected (ByteArrayHelper/ethMacStringToByteArrayUnchecked in-str)))
    (is (= in-str (FormatUtils/mac expected)))))

(deftest ipv4-string-to-byte-array-1_2_3_4-unchecked-test
  (let [in-str "1.2.3.4"
        expected (byte-array (map byte [1 2 3 4]))]
    (is (Arrays/equals expected (ByteArrayHelper/ipv4StringToByteArrayUnchecked in-str)))
    (is (= in-str (FormatUtils/ip expected)))))

(deftest ipv4-string-to-byte-array-127_128_129_130-unchecked-test
  (let [in-str "127.128.129.130"
        expected (byte-array (map byte [127 -128 -127 -126]))]
    (is (Arrays/equals expected (ByteArrayHelper/ipv4StringToByteArrayUnchecked in-str)))
    (is (= in-str (FormatUtils/ip expected)))))

(deftest ipv4-string-to-byte-array-252_253_254_255-unchecked-test
  (let [in-str "252.253.254.255"
        expected (byte-array (map byte [-4 -3 -2 -1]))]
    (is (Arrays/equals expected (ByteArrayHelper/ipv4StringToByteArrayUnchecked in-str)))
    (is (= in-str (FormatUtils/ip expected)))))

(deftest generate-packet-data-ethernet-test
  (let [pkt-description-map {"len" 20, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0"}
        expected-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 0 0 0 0 0 0 0 0]
        expected-ba (byte-array (map byte expected-vec))
        result-ba (generate-packet-data pkt-description-map)]
    (is (= expected-vec (vec result-ba)))
    (is (Arrays/equals expected-ba result-ba))))

(deftest generate-packet-data-ipv4-with-automatically-calculated-checksum-test
  (let [pkt-description-map {"len" 40, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                             "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3,
                             "ipTtl" 7, "ipSrc" "1.2.3.4"}
        expected-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0
                      69 0 0 26 0 3 64 0 7 0 115 -34 1 2 3 4 -4 -3 -2 -1
                      0 0 0 0 0 0]
        expected-ba (byte-array (map byte expected-vec))
        result-ba (generate-packet-data pkt-description-map)]
    (is (= expected-vec (vec result-ba)))
    (is (Arrays/equals expected-ba result-ba))))

(deftest generate-packet-data-ipv4-with-manually-set-checksum-test
  (let [pkt-description-map {"len" 40, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                             "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3,
                             "ipTtl" 7, "ipChecksum" 123, "ipSrc" "1.2.3.4"}
        expected-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0
                      69 0 0 26 0 3 64 0 7 0 0 123 1 2 3 4 -4 -3 -2 -1
                      0 0 0 0 0 0]
        expected-ba (byte-array (map byte expected-vec))
        result-ba (generate-packet-data pkt-description-map)]
    (is (= expected-vec (vec result-ba)))
    (is (Arrays/equals expected-ba result-ba))))

(deftest generate-packet-data-ipv4-with-icmp-test
  (let [pkt-description-map {"len" 54, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                             "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3, "ipType" 1,
                             "ipTtl" 7, "ipSrc" "1.2.3.4",
                             "icmpType" 8, "icmpEchoSeq" "bar",
                             "icmpId" 123, "icmpSeqNo" 12, "icmpData" "abcd"}
        expected-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0
                      69 0 0 40 0 3 64 0 7 1 115 -49 1 2 3 4 -4 -3 -2 -1
                      8 0 50 -78 0 123 0 12 0 0 0 0 0 0 0 0 97 98 99 100]
        expected-ba (byte-array (map byte expected-vec))
        result-ba (generate-packet-data pkt-description-map)]
    (is (= expected-vec (vec result-ba)))
    (is (Arrays/equals expected-ba result-ba))))

