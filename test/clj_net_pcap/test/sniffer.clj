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
    :doc "Clojure jNetPcap sniffer tests"}
  clj-net-pcap.test.sniffer
  (:use clojure.test
        clj-net-pcap.pcap
        clj-net-pcap.sniffer
        clj-assorted-utils.util)
  (:import (java.util.concurrent LinkedBlockingQueue)))

(def receive-delay 1000)

;(deftest test-sniffer
;  (let [was-run (prepare-flag)
;        handler-fn (fn [_ _ _] (set-flag was-run))
;        pcap (create-and-activate-online-pcap lo)
;        sniffer (create-and-start-sniffer pcap handler-fn nil)]
;    (is (not (flag-set? was-run)))
;    (Thread/sleep receive-delay)
;    (.inject (pcap) (byte-array 1 (byte 0)))
;    (await-flag was-run)
;    (is (flag-set? was-run))
;    (stop-sniffer sniffer)))

(deftest test-forwarder
  (let [was-run (prepare-flag)
        forwarder-fn (fn [_] (set-flag was-run))
        queue (LinkedBlockingQueue.)
        forwarder (create-and-start-forwarder queue forwarder-fn false)]
    (is (not (flag-set? was-run)))
    (.offer queue 12345)
    (await-flag was-run)
    (is (flag-set? was-run))
    (stop-forwarder forwarder)))

(deftest sniffer-forwarder-interaction
  (let [was-run (prepare-flag)
        queue (LinkedBlockingQueue.)
        handler-fn (fn [ph bb u] (.offer queue 12345))
        forwarder-fn (fn [_] (set-flag was-run))
        forwarder (create-and-start-forwarder queue forwarder-fn false)
        pcap (create-and-activate-online-pcap lo)
        sniffer (create-and-start-sniffer pcap handler-fn)]
    (Thread/sleep receive-delay)
    (exec-blocking "ping -c 1 localhost")
    (await-flag was-run)
    (is (flag-set? was-run))
    (stop-sniffer sniffer)
    (stop-forwarder forwarder)))
