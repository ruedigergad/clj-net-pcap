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
    :doc "Tests for sending packets via pcap."}
  clj-net-pcap.test.pcap-bulk
  (:use clojure.test
        clj-assorted-utils.util
        clj-net-pcap.core
        clj-net-pcap.packet-gen
        clj-net-pcap.pcap
        clj-net-pcap.pcap-data
        clj-net-pcap.sniffer)
  (:import (java.util Arrays)
           (java.nio ByteBuffer)))

(def test-pkt-bytes [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0
                     69 0 0 40 0 3 64 0 7 1 115 -49 1 2 3 4 -4 -3 -2 -1
                     8 0 50 -78 0 123 0 12 0 0 0 0 0 0 0 0 97 98 99 100])

(def test-pkt-descr-map {"len" 54, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                         "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3, "ipType" 1,
                         "ipTtl" 7, "ipSrc" "1.2.3.4",
                         "icmpType" 8, "icmpEchoSeq" "bar",
                         "icmpId" 123, "icmpSeqNo" 12, "data" "abcd"})



(deftest cljnetpcap-send-and-receive-bytes-packet-count-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        cntr (counter)
        forwarder-fn (fn [_]
                       (cntr inc))
        cljnetpcap (binding [clj-net-pcap.core/*bulk-size* 10
                             clj-net-pcap.core/*emit-raw-data* true]
                     (create-and-start-online-cljnetpcap forwarder-fn lo))]
    (sleep 100)
    (cljnetpcap :send-bytes-packet ba 10 10)
    (sleep 300)
    (is (= 1 (cntr)))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-packet-maps-count-test
  (let [cntr (counter)
        forwarder-fn (fn [_]
                       (cntr inc))
        cljnetpcap (binding [clj-net-pcap.core/*bulk-size* 10
                             clj-net-pcap.core/*emit-raw-data* true]
                     (create-and-start-online-cljnetpcap forwarder-fn lo))]
    (sleep 100)
    (doseq [x (range 1 11)]
      (cljnetpcap :send-packet-map (assoc test-pkt-descr-map "icmpSeqNo" x)))
    (sleep 300)
    (is (= 1 (cntr)))
    (stop-cljnetpcap cljnetpcap)))

