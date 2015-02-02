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

(deftest moving-average-calculator-test-1
  (let [mvg-avg-calc (create-moving-average-calculator 3)]
    (is (= 0 (mvg-avg-calc)))
    (mvg-avg-calc 1000)
    (is (= (/ 1000 3) (mvg-avg-calc)))
    (mvg-avg-calc 1000)
    (is (= (/ 2000 3) (mvg-avg-calc)))
    (mvg-avg-calc 1000)
    (is (= 1000 (mvg-avg-calc)))))

(deftest moving-average-calculator-test-2
  (let [mvg-avg-calc (create-moving-average-calculator 3)]
    (mvg-avg-calc 1000)
    (mvg-avg-calc 2000)
    (mvg-avg-calc 3000)
    (is (= 2000 (mvg-avg-calc)))))

(deftest moving-average-calculator-test-3
  (let [mvg-avg-calc (create-moving-average-calculator 3)]
    (mvg-avg-calc 1000)
    (mvg-avg-calc 1000)
    (mvg-avg-calc 1000)
    (mvg-avg-calc 2000)
    (mvg-avg-calc 3000)
    (is (= 2000 (mvg-avg-calc)))))

(deftest determine-max-capture-rate-test-1
  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        threshold 0.01
        interpolation 3
        max-cap-rate-det (create-max-capture-rate-determinator threshold interpolation)]
    (is (= -1 (max-cap-rate-det stat-1)))
    (is (= -1 (max-cap-rate-det stat-2)))
    (is (= 8000 (max-cap-rate-det stat-3)))))

(deftest determine-max-capture-rate-test-2
  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 20, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 40, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 60, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        threshold 0.01
        interpolation 3
        max-cap-rate-det (create-max-capture-rate-determinator threshold interpolation)]
    (is (= -1 (max-cap-rate-det stat-1)))
    (is (= -1 (max-cap-rate-det stat-2)))
    (is (= -1 (max-cap-rate-det stat-3)))))

(deftest determine-max-capture-rate-test-3
  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 4020, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        stat-4 {"forwarder-failed" 0, "out-dropped" 6020, "out-queued" 0, "recv" 40000, "drop" 0, "ifdrop" 0}
        stat-5 {"forwarder-failed" 0, "out-dropped" 8020, "out-queued" 0, "recv" 50000, "drop" 0, "ifdrop" 0}
        stat-6 {"forwarder-failed" 0, "out-dropped" 10020, "out-queued" 0, "recv" 60000, "drop" 0, "ifdrop" 0}
        threshold 0.01
        interpolation 3
        max-cap-rate-det (create-max-capture-rate-determinator threshold interpolation)]
    (is (= -1 (max-cap-rate-det stat-1)))
    (is (= -1 (max-cap-rate-det stat-2)))
    (is (= -1 (max-cap-rate-det stat-3)))
    (is (= -1 (max-cap-rate-det stat-4)))
    (is (= -1 (max-cap-rate-det stat-5)))
    (is (= 8000 (max-cap-rate-det stat-6)))))

(deftest determine-max-capture-rate-test-4
  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 1500, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 3000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        threshold 0.01
        interpolation 3
        max-cap-rate-det (create-max-capture-rate-determinator threshold interpolation)]
    (is (= -1 (max-cap-rate-det stat-1)))
    (is (= -1 (max-cap-rate-det stat-2)))
    (is (= 8000 (max-cap-rate-det stat-3)))))

(deftest self-adaptation-controller-initialization-test
  (let [initial-dsl-expr [{:a "A"} {:b "B"} {:c "C"}]
        dynamic-dsl-expr (atom nil)
        self-adpt-ctrlr (create-self-adaptation-controller initial-dsl-expr dynamic-dsl-expr)]
    (is (= initial-dsl-expr @dynamic-dsl-expr))))
