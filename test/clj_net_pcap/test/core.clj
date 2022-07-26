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
  (:require
   (clojure [test :as test])
   (clj-assorted-utils [util :as utils])
   (clj-net-pcap [core :as core])
   (clj-net-pcap [pcap :as pcap])))

(test/deftest cljnetpcap-test
  (let [was-run (utils/prepare-flag)
        forwarder-fn (fn [_] (utils/set-flag was-run))
        filter-expression ""
        device pcap/lo
        cljnetpcap (core/create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (utils/exec-blocking "ping -c 1 localhost")
    (utils/await-flag was-run)
    (test/is (utils/flag-set? was-run))
    (core/stop-cljnetpcap cljnetpcap)))

(test/deftest test-unsupported-operation-throws-exception
  (let [forwarder-fn (fn [_])
        filter-expression "tcp[tcpflags] & tcp-syn != 0"
        device pcap/lo
        cljnetpcap (core/create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (test/is (thrown? RuntimeException (cljnetpcap :unsupported-operation)))
    (core/stop-cljnetpcap  cljnetpcap)))

(test/deftest test-get-filter
  (let [forwarder-fn (fn [_])
        filter-expression "tcp[tcpflags] & tcp-syn != 0"
        device pcap/lo
        cljnetpcap (core/create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (test/is (= (type []) (type (core/get-filters cljnetpcap))))
    (test/is (= "tcp[tcpflags] & tcp-syn != 0" (first (core/get-filters cljnetpcap))))
    (core/stop-cljnetpcap cljnetpcap)))

(test/deftest test-add-filter
  (let [forwarder-fn (fn [_])
        filter-expression ""
        device pcap/lo
        cljnetpcap (core/create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (test/is (empty? (core/get-filters cljnetpcap)))
    (core/add-filter cljnetpcap "tcp[tcpflags] & tcp-syn != 0")
    (test/is (= "tcp[tcpflags] & tcp-syn != 0" (first (core/get-filters cljnetpcap))))
    (core/stop-cljnetpcap cljnetpcap)))

(test/deftest test-do-not-add-empty-filter
  (let [forwarder-fn (fn [_])
        filter-expression ""
        device pcap/lo
        cljnetpcap (core/create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (test/is (empty? (core/get-filters cljnetpcap)))
    (core/add-filter cljnetpcap "")
    (test/is (empty? (core/get-filters cljnetpcap)))
    (core/stop-cljnetpcap cljnetpcap)))

(test/deftest test-remove-last-filter
  (let [forwarder-fn (fn [_])
        filter-expression "tcp[tcpflags] & tcp-syn != 0"
        device pcap/lo
        cljnetpcap (core/create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (test/is (= 1 (count (core/get-filters cljnetpcap))))
    (core/remove-last-filter cljnetpcap)
    (test/is (empty? (core/get-filters cljnetpcap)))
    (core/stop-cljnetpcap cljnetpcap)))

(test/deftest test-remove-filter
  (let [forwarder-fn (fn [_])
        filter-expression "tcp[tcpflags] & tcp-syn != 0"
        device pcap/lo
        cljnetpcap (core/create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (test/is (= 1 (count (core/get-filters cljnetpcap))))
    (core/remove-filter cljnetpcap "tcp[tcpflags] & tcp-syn != 0")
    (test/is (empty? (core/get-filters cljnetpcap)))
    (core/stop-cljnetpcap cljnetpcap)))

(test/deftest test-simple-get-stats
  (let [forwarder-fn (fn [_])
        filter-expression "less 1"
        device pcap/lo
        cljnetpcap (core/create-and-start-online-cljnetpcap forwarder-fn device filter-expression)]
    (test/is (map? (core/get-stats cljnetpcap)))
    (core/stop-cljnetpcap  cljnetpcap)))
