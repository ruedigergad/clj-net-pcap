;;;
;;; Copyright (C) 2012 Ruediger Gad
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
    :doc "Tests for clj-net-pcap integration"}
  clj-net-pcap.test.core
  (:use clojure.test
        clj-net-pcap.core
        clj-assorted-utils.util))

(deftest cljnetpcap-test
  (let [was-run (prepare-flag)
        forwarder-fn (fn [_] (set-flag was-run))
        filter-expression ""
        device "lo"
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (exec-blocking "ping -c 1 localhost")
    (await-flag was-run)
    (is (flag-set? was-run))
    (stop-cljnetpcap cljnetpcap)))

(deftest test-unsupported-operation-throws-exception
  (let [forwarder-fn (fn [_])
        filter-expression "tcp[tcpflags] & tcp-syn != 0"
        device "lo"
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (is (thrown? RuntimeException (cljnetpcap :unsupported-operation)))
    (stop-cljnetpcap  cljnetpcap)))

(deftest test-get-filter
  (let [forwarder-fn (fn [_])
        filter-expression "tcp[tcpflags] & tcp-syn != 0"
        device "lo"
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (is (= (type []) (type (get-filters cljnetpcap))))
    (is (= "tcp[tcpflags] & tcp-syn != 0" (first (get-filters cljnetpcap))))
    (stop-cljnetpcap cljnetpcap)))

(deftest test-add-filter
  (let [forwarder-fn (fn [_])
        filter-expression ""
        device "lo"
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (is (empty? (get-filters cljnetpcap)))
    (add-filter cljnetpcap "tcp[tcpflags] & tcp-syn != 0")
    (is (= "tcp[tcpflags] & tcp-syn != 0" (first (get-filters cljnetpcap))))
    (stop-cljnetpcap cljnetpcap)))

(deftest test-do-not-add-empty-filter
  (let [forwarder-fn (fn [_])
        filter-expression ""
        device "lo"
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (is (empty? (get-filters cljnetpcap)))
    (add-filter cljnetpcap "")
    (is (empty? (get-filters cljnetpcap)))
    (stop-cljnetpcap cljnetpcap)))

(deftest test-remove-last-filter
  (let [forwarder-fn (fn [_])
        filter-expression "tcp[tcpflags] & tcp-syn != 0"
        device "lo"
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (is (= 1 (count (get-filters cljnetpcap))))
    (remove-last-filter cljnetpcap)
    (is (empty? (get-filters cljnetpcap)))
    (stop-cljnetpcap cljnetpcap)))

(deftest test-remove-filter
  (let [forwarder-fn (fn [_])
        filter-expression "tcp[tcpflags] & tcp-syn != 0"
        device "lo"
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (is (= 1 (count (get-filters cljnetpcap))))
    (remove-filter cljnetpcap "tcp[tcpflags] & tcp-syn != 0")
    (is (empty? (get-filters cljnetpcap)))
    (stop-cljnetpcap cljnetpcap)))

(deftest test-simple-get-stats
  (let [forwarder-fn (fn [_])
        filter-expression "less 1"
        device "lo"
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (is (map? (get-stats cljnetpcap)))
    (stop-cljnetpcap  cljnetpcap)))

