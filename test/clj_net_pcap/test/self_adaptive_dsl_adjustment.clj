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
    :doc "Tests for applying DSL expressions with self-adaptivity."}
  clj-net-pcap.test.self-adaptive-dsl-adjustment
  (:require
   (clojure [test :as test])
   (clj-net-pcap [self-adaptive-dsl-adjustment :as dsl-adapt])))

(test/deftest stat-delta-test
  (let [stat-1 {"forwarder-failed" 1, "out-dropped" 2, "out-queued" 3, "recv" 4, "drop" 5, "ifdrop" 6}
        stat-2 {"forwarder-failed" 6, "out-dropped" 5, "out-queued" 4, "recv" 5, "drop" 6, "ifdrop" 7}
        expected-delta-1 {"forwarder-failed" 1, "out-dropped" 2, "out-queued" 3, "recv" 4, "drop" 5, "ifdrop" 6}
        expected-delta-2 {"forwarder-failed" 5, "out-dropped" 3, "out-queued" 1, "recv" 1, "drop" 1, "ifdrop" 1}
        stat-d-cntr (dsl-adapt/create-stat-delta-counter)]
    (test/is (= expected-delta-1 (stat-d-cntr stat-1)))
    (test/is (= expected-delta-2 (stat-d-cntr stat-2)))))

(test/deftest get-dropped-sum-test
  (let [delta {"forwarder-failed" 1, "out-dropped" 2, "out-queued" 3, "recv" 4, "drop" 5, "ifdrop" 6}]
    (test/is (= 13 (dsl-adapt/get-dropped-sum delta)))))

(test/deftest simple-repetition-detection-test-1
  (let [detector (dsl-adapt/create-repetition-detector 3)]
    (test/is (not (detector (fn [] true))))
    (test/is (not (detector (fn [] true))))
    (test/is (detector (fn [] true)))
    (test/is (not (detector (fn [] true))))))

(test/deftest simple-repetition-detection-test-2
  (let [detector (dsl-adapt/create-repetition-detector 3)]
    (test/is (not (detector (fn [] true))))
    (test/is (not (detector (fn [] true))))
    (test/is (not (detector (fn [] false))))
    (test/is (not (detector (fn [] true))))
    (test/is (not (detector (fn [] true))))
    (test/is (detector (fn [] true)))
    (test/is (not (detector (fn [] true))))))

(test/deftest moving-average-calculator-test-1
  (let [mvg-avg-calc (dsl-adapt/create-moving-average-calculator 3)]
    (test/is (= 0 (mvg-avg-calc)))
    (mvg-avg-calc 1000)
    (test/is (= (/ 1000 3) (mvg-avg-calc)))
    (mvg-avg-calc 1000)
    (test/is (= (/ 2000 3) (mvg-avg-calc)))
    (mvg-avg-calc 1000)
    (test/is (= 1000 (mvg-avg-calc)))))

(test/deftest moving-average-calculator-test-2
  (let [mvg-avg-calc (dsl-adapt/create-moving-average-calculator 3)]
    (mvg-avg-calc 1000)
    (mvg-avg-calc 2000)
    (mvg-avg-calc 3000)
    (test/is (= 2000 (mvg-avg-calc)))))

(test/deftest moving-average-calculator-test-3
  (let [mvg-avg-calc (dsl-adapt/create-moving-average-calculator 3)]
    (mvg-avg-calc 1000)
    (mvg-avg-calc 1000)
    (mvg-avg-calc 1000)
    (mvg-avg-calc 2000)
    (mvg-avg-calc 3000)
    (test/is (= 2000 (mvg-avg-calc)))))

(test/deftest determine-max-capture-rate-test-1
  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        threshold 0.01
        interpolation 3
        max-cap-rate-det (dsl-adapt/create-max-capture-rate-determinator threshold interpolation)]
    (test/is (= -1 (max-cap-rate-det stat-1)))
    (test/is (= -1 (max-cap-rate-det stat-2)))
    (test/is (= 9900.0 (max-cap-rate-det stat-3)))))

;FIXME: Update test.
;(test/deftest determine-max-capture-rate-test-2
;  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 20, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
;        stat-2 {"forwarder-failed" 0, "out-dropped" 40, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
;        stat-3 {"forwarder-failed" 0, "out-dropped" 60, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
;        threshold 0.01
;        interpolation 3
;        max-cap-rate-det (dsl-adapt/create-max-capture-rate-determinator threshold interpolation)]
;    (test/is (= -1 (max-cap-rate-det stat-1)))
;    (test/is (= -1 (max-cap-rate-det stat-2)))
;    (test/is (= -1 (max-cap-rate-det stat-3)))))

;FIXME: Update test.
;(test/deftest determine-max-capture-rate-test-3
;  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
;        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
;        stat-3 {"forwarder-failed" 0, "out-dropped" 4020, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
;        stat-4 {"forwarder-failed" 0, "out-dropped" 6020, "out-queued" 0, "recv" 40000, "drop" 0, "ifdrop" 0}
;        stat-5 {"forwarder-failed" 0, "out-dropped" 8020, "out-queued" 0, "recv" 50000, "drop" 0, "ifdrop" 0}
;        stat-6 {"forwarder-failed" 0, "out-dropped" 10020, "out-queued" 0, "recv" 60000, "drop" 0, "ifdrop" 0}
;        threshold 0.01
;        interpolation 3
;        max-cap-rate-det (dsl-adapt/create-max-capture-rate-determinator threshold interpolation)]
;    (test/is (= -1 (max-cap-rate-det stat-1)))
;    (test/is (= -1 (max-cap-rate-det stat-2)))
;    (test/is (= -1 (max-cap-rate-det stat-3)))
;    (test/is (= -1 (max-cap-rate-det stat-4)))
;    (test/is (= -1 (max-cap-rate-det stat-5)))
;    (test/is (= 9900.0 (max-cap-rate-det stat-6)))))

(test/deftest determine-max-capture-rate-test-4
  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 1500, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 3000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        threshold 0.01
        interpolation 3
        max-cap-rate-det (dsl-adapt/create-max-capture-rate-determinator threshold interpolation)]
    (test/is (= -1 (max-cap-rate-det stat-1)))
    (test/is (= -1 (max-cap-rate-det stat-2)))
    (test/is (= 9900.0 (max-cap-rate-det stat-3)))))

(test/deftest determine-max-capture-rate-test-5
  (let [stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        stat-4 {"forwarder-failed" 0, "out-dropped" 8000, "out-queued" 0, "recv" 40000, "drop" 0, "ifdrop" 0}
        stat-5 {"forwarder-failed" 0, "out-dropped" 10000, "out-queued" 0, "recv" 50000, "drop" 0, "ifdrop" 0}
        stat-6 {"forwarder-failed" 0, "out-dropped" 12000, "out-queued" 0, "recv" 60000, "drop" 0, "ifdrop" 0}
        threshold 0.01
        interpolation 3
        max-cap-rate-det (dsl-adapt/create-max-capture-rate-determinator threshold interpolation)]
    (test/is (= -1 (max-cap-rate-det stat-1)))
    (test/is (= -1 (max-cap-rate-det stat-2)))
    (test/is (= 9900.0 (max-cap-rate-det stat-3)))
    (test/is (= -1 (max-cap-rate-det stat-4)))
    (test/is (= -1 (max-cap-rate-det stat-5)))
    (test/is (= 9900.0 (max-cap-rate-det stat-6)))))

(test/deftest self-adaptation-controller-initialization-test
  (let [initial-dsl-expr [{:a "A"} {:b "B"} {:c "C"}]
        dynamic-dsl-expr (atom nil)
        threshold 0.01
        interpolation 3
        inactivity 2
        _ (dsl-adapt/create-self-adaptation-controller initial-dsl-expr dynamic-dsl-expr threshold interpolation inactivity)]
    (test/is (= initial-dsl-expr @dynamic-dsl-expr))))

(test/deftest self-adaptation-controller-cap-rate-calc-test-1
  (let [initial-dsl-expr [{:a "A"} {:b "B"} {:c "C"}]
        dynamic-dsl-expr (atom nil)
        threshold 0.01
        interpolation 3
        inactivity 2
        stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        self-adpt-ctrlr (dsl-adapt/create-self-adaptation-controller initial-dsl-expr dynamic-dsl-expr threshold interpolation inactivity)]
    (test/is (= initial-dsl-expr @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-1)
    (self-adpt-ctrlr stat-2)
    (self-adpt-ctrlr stat-3)
    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))))

(test/deftest self-adaptation-controller-cap-rate-calc-test-2
  (let [initial-dsl-expr [{:a "A"} {:b "B"} {:c "C"}]
        dynamic-dsl-expr (atom nil)
        threshold 0.01
        interpolation 3
        inactivity 0
        stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        stat-4 {"forwarder-failed" 0, "out-dropped" 8000, "out-queued" 0, "recv" 40000, "drop" 0, "ifdrop" 0}
        stat-5 {"forwarder-failed" 0, "out-dropped" 10000, "out-queued" 0, "recv" 50000, "drop" 0, "ifdrop" 0}
        stat-6 {"forwarder-failed" 0, "out-dropped" 12000, "out-queued" 0, "recv" 60000, "drop" 0, "ifdrop" 0}
        self-adpt-ctrlr (dsl-adapt/create-self-adaptation-controller initial-dsl-expr dynamic-dsl-expr threshold interpolation inactivity)]
    (test/is (= initial-dsl-expr @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-1)
    (self-adpt-ctrlr stat-2)
    (self-adpt-ctrlr stat-3)
    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-4)
    (self-adpt-ctrlr stat-5)
    (self-adpt-ctrlr stat-6)
    (test/is (= [{:c "C"}] @dynamic-dsl-expr))))

;FIXME: Update test.
;(test/deftest self-adaptation-controller-inactivity-test
;  (let [initial-dsl-expr [{:a "A"} {:b "B"} {:c "C"}]
;        dynamic-dsl-expr (atom nil)
;        threshold 0.01
;        interpolation 3
;        inactivity 2
;        stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
;        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
;        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
;        stat-4 {"forwarder-failed" 0, "out-dropped" 8000, "out-queued" 0, "recv" 40000, "drop" 0, "ifdrop" 0}
;        stat-5 {"forwarder-failed" 0, "out-dropped" 10000, "out-queued" 0, "recv" 50000, "drop" 0, "ifdrop" 0}
;        stat-6 {"forwarder-failed" 0, "out-dropped" 12000, "out-queued" 0, "recv" 60000, "drop" 0, "ifdrop" 0}
;        stat-7 {"forwarder-failed" 0, "out-dropped" 14000, "out-queued" 0, "recv" 70000, "drop" 0, "ifdrop" 0}
;        stat-8 {"forwarder-failed" 0, "out-dropped" 16000, "out-queued" 0, "recv" 80000, "drop" 0, "ifdrop" 0}
;        self-adpt-ctrlr (dsl-adapt/create-self-adaptation-controller initial-dsl-expr dynamic-dsl-expr threshold interpolation inactivity)]
;    (test/is (= initial-dsl-expr @dynamic-dsl-expr))
;    (self-adpt-ctrlr stat-1)
;    (self-adpt-ctrlr stat-2)
;    (self-adpt-ctrlr stat-3)
;    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))
;    (self-adpt-ctrlr stat-4)
;    (self-adpt-ctrlr stat-5)
;    (self-adpt-ctrlr stat-6)
;    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))
;    (self-adpt-ctrlr stat-7)
;    (self-adpt-ctrlr stat-8)
;    (test/is (= [{:c "C"}] @dynamic-dsl-expr))))

(test/deftest self-adaptation-controller-restore-full-dsl-on-slowdown-test
  (let [initial-dsl-expr [{:a "A"} {:b "B"} {:c "C"}]
        dynamic-dsl-expr (atom nil)
        threshold 0.01
        interpolation 3
        inactivity 2
        stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        stat-4 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 36000, "drop" 0, "ifdrop" 0}
        stat-5 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 42000, "drop" 0, "ifdrop" 0}
        stat-6 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 48000, "drop" 0, "ifdrop" 0}
        self-adpt-ctrlr (dsl-adapt/create-self-adaptation-controller initial-dsl-expr dynamic-dsl-expr threshold interpolation inactivity)]
    (test/is (= initial-dsl-expr @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-1)
    (self-adpt-ctrlr stat-2)
    (self-adpt-ctrlr stat-3)
    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-4)
    (self-adpt-ctrlr stat-5)
    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-6)
    (test/is (= initial-dsl-expr @dynamic-dsl-expr))))

(test/deftest self-adaptation-controller-limit-dsl-on-speedup-test
  (let [initial-dsl-expr [{:a "A"} {:b "B"} {:c "C"}]
        dynamic-dsl-expr (atom nil)
        threshold 0.01
        interpolation 3
        inactivity 2
        stat-1 {"forwarder-failed" 0, "out-dropped" 2000, "out-queued" 0, "recv" 10000, "drop" 0, "ifdrop" 0}
        stat-2 {"forwarder-failed" 0, "out-dropped" 4000, "out-queued" 0, "recv" 20000, "drop" 0, "ifdrop" 0}
        stat-3 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 30000, "drop" 0, "ifdrop" 0}
        stat-4 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 36000, "drop" 0, "ifdrop" 0}
        stat-5 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 42000, "drop" 0, "ifdrop" 0}
        stat-6 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 48000, "drop" 0, "ifdrop" 0}
        stat-7 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 54000, "drop" 0, "ifdrop" 0}
        stat-8 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 60000, "drop" 0, "ifdrop" 0}
        stat-9 {"forwarder-failed" 0, "out-dropped" 6000, "out-queued" 0, "recv" 70000, "drop" 0, "ifdrop" 0}
        self-adpt-ctrlr (dsl-adapt/create-self-adaptation-controller initial-dsl-expr dynamic-dsl-expr threshold interpolation inactivity)]
    (test/is (= initial-dsl-expr @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-1)
    (self-adpt-ctrlr stat-2)
    (self-adpt-ctrlr stat-3)
    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-4)
    (self-adpt-ctrlr stat-5)
    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-6)
    (test/is (= initial-dsl-expr @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-7)
    (self-adpt-ctrlr stat-8)
    (test/is (= initial-dsl-expr @dynamic-dsl-expr))
    (self-adpt-ctrlr stat-9)
    (test/is (= [{:b "B"} {:c "C"}] @dynamic-dsl-expr))))
