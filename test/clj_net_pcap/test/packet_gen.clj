;;;
;;; Copyright (C) 2014 Ruediger Gad
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
        clj-net-pcap.core
        clj-assorted-utils.util)
  (:import (clj_net_pcap ByteArrayHelper PacketHeaderDataBean)
           (java.util Arrays)
           (org.jnetpcap.packet.format FormatUtils)))

(deftest eth-mac-string-to-byte-array-01_02_03_04_05_06-test
  (let [in-str "01:02:03:04:05:06"
        expected (byte-array (map byte [1 2 3 4 5 6]))]
    (is (Arrays/equals expected (ByteArrayHelper/ethMacStringToByteArray in-str)))
    (is (= in-str (FormatUtils/mac expected)))))

(deftest eth-mac-string-to-byte-array-10_11_12_1A_1B_1C-test
  (let [in-str "10:11:12:1A:1B:1C"
        expected (byte-array (map byte [16 17 18 26 27 28]))]
    (is (Arrays/equals expected (ByteArrayHelper/ethMacStringToByteArray in-str)))
    (is (= in-str (FormatUtils/mac expected)))))

(deftest eth-mac-string-to-byte-array-81_82_83_84_85_86-test
  (let [in-str "81:82:83:84:85:86"
        expected (byte-array (map byte [-127 -126 -125 -124 -123 -122]))]
    (is (Arrays/equals expected (ByteArrayHelper/ethMacStringToByteArray in-str)))
    (is (= in-str (FormatUtils/mac expected)))))

(deftest eth-mac-string-to-byte-array-FF_FE_FD_F2_F1_F0-test
  (let [in-str "FF:FE:FD:F2:F1:F0"
        expected (byte-array (map byte [-1 -2 -3 -14 -15 -16]))]
    (is (Arrays/equals expected (ByteArrayHelper/ethMacStringToByteArray in-str)))
    (is (= in-str (FormatUtils/mac expected)))))

(deftest ipv4-string-to-byte-array-1_2_3_4-test
  (let [in-str "1.2.3.4"
        expected (byte-array (map byte [1 2 3 4]))]
    (is (Arrays/equals expected (ByteArrayHelper/ipv4StringToByteArray in-str)))
    (is (= in-str (FormatUtils/ip expected)))))

