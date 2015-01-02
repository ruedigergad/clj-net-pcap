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
  clj-net-pcap.test.pcap-send
  (:use clojure.test
        clj-assorted-utils.util
        clj-net-pcap.core
        clj-net-pcap.packet-gen
        clj-net-pcap.pcap
        clj-net-pcap.sniffer)
  (:import (java.util Arrays)
           (java.nio ByteBuffer)))

(def test-pkt-bytes [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0
                     69 0 0 40 0 3 64 0 7 1 115 -49 1 2 3 4 -4 -3 -2 -1
                     8 0 50 -78 0 123 0 12 0 0 0 0 0 0 0 0 97 98 99 100])

(deftest naive-pcap-send-byte-array-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        pcap (create-and-activate-online-pcap lo)]
    (pcap :send-bytes-packet ba)
    (close-pcap pcap)))

(deftest pcap-send-and-sniff-byte-array-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        bb (ByteBuffer/allocate (alength ba))
        pcap (create-and-activate-online-pcap lo)
        flag (prepare-flag)
        handler (fn [ph buf _]
                  (println ph buf)
                  (doto bb
                    (.put buf)
                    (.flip))
                  (set-flag flag))
        sniffer (create-and-start-sniffer pcap handler)]
    ; Give the sniffer a little time to start before we actually send the packet.
    (sleep 100)
    (pcap :send-bytes-packet ba)
    (await-flag flag)
    (is (flag-set? flag))
    (is (Arrays/equals ba (.array bb)))
    (close-pcap pcap)))

