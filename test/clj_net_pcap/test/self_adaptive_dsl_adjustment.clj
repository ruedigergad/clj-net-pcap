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
    :doc "Tests for applying DSL expressions with self-adaptivity."}
  clj-net-pcap.test.self-adaptive-dsl-adjustment
  (:use clojure.test
        clj-net-pcap.self-adaptive-dsl-adjustment
        clj-assorted-utils.util)
  (:import (clj_net_pcap PacketHeaderDataBeanIpv4UdpOnly)))

(deftest stat-delta-test
  (let [stat-1 {"forwarder-failed" 1, "out-dropped" 2, "out-queued" 3, "recv" 4, "drop" 5, "ifdrop" 6}
        stat-2 {"forwarder-failed" 6, "out-dropped" 5, "out-queued" 4, "recv" 5, "drop" 6, "ifdrop" 7}
        expected-delta-1 {"forwarder-failed" 1, "out-dropped" 2, "out-queued" 3, "recv" 4, "drop" 5, "ifdrop" 6}
        expected-delta-2 {"forwarder-failed" 5, "out-dropped" 3, "out-queued" 1, "recv" 1, "drop" 1, "ifdrop" 1}
        stat-d-cntr (create-stat-delta-counter)]
    (is (= expected-delta-1 (stat-d-cntr stat-1)))
    (is (= expected-delta-2 (stat-d-cntr stat-2)))))

(deftest get-dropped-sum-test
  (let [delta {"forwarder-failed" 1, "out-dropped" 2, "out-queued" 3, "recv" 4, "drop" 5, "ifdrop" 6}]
    (is (= 13 (get-dropped-sum delta)))))

(deftest simple-repetition-detection-test-1
  (let [detector (create-repetition-detector 3)]
    (is (not (detector (fn [] true))))
    (is (not (detector (fn [] true))))
    (is (detector (fn [] true)))
    (is (not (detector (fn [] true))))))

(deftest simple-repetition-detection-test-2
  (let [detector (create-repetition-detector 3)]
    (is (not (detector (fn [] true))))
    (is (not (detector (fn [] true))))
    (is (not (detector (fn [] false))))
    (is (not (detector (fn [] true))))
    (is (not (detector (fn [] true))))
    (is (detector (fn [] true)))
    (is (not (detector (fn [] true))))))

