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
  (:require
   (clojure [test :as test])
   (clj-assorted-utils [util :as utils])
   (clj-net-pcap [pcap :as pcap])
   (clj-net-pcap [sniffer :as sniffer]))
  (:import (java.util.concurrent LinkedBlockingQueue)))

(def receive-delay 1000)

;(test/deftest test-sniffer
;  (let [was-run (utils/prepare-flag)
;        handler-fn (fn [_ _ _] (utils/set-flag was-run))
;        pcap (create-and-activate-online-pcap lo)
;        sniffer (create-and-start-sniffer pcap handler-fn nil)]
;    (test/is (not (utils/flag-set? was-run)))
;    (Thread/sleep receive-delay)
;    (.inject (pcap) (byte-array 1 (byte 0)))
;    (utils/await-flag was-run)
;    (test/is (utils/flag-set? was-run))
;    (stop-sniffer sniffer)))

(test/deftest test-forwarder
  (let [was-run (utils/prepare-flag)
        forwarder-fn (fn [_] (utils/set-flag was-run))
        queue (LinkedBlockingQueue.)
        forwarder (sniffer/create-and-start-forwarder queue forwarder-fn false)]
    (test/is (not (utils/flag-set? was-run)))
    (.offer queue 12345)
    (utils/await-flag was-run)
    (test/is (utils/flag-set? was-run))
    (sniffer/stop-forwarder forwarder)))

(test/deftest sniffer-forwarder-interaction
  (let [was-run (utils/prepare-flag)
        queue (LinkedBlockingQueue.)
        handler-fn (fn [_ _ _] (.offer queue 12345))
        forwarder-fn (fn [_] (utils/set-flag was-run))
        forwarder (sniffer/create-and-start-forwarder queue forwarder-fn false)
        pcap (pcap/create-and-activate-online-pcap pcap/lo)
        sniffer (sniffer/create-and-start-sniffer pcap handler-fn)]
    (Thread/sleep receive-delay)
    (utils/exec-blocking "ping -c 1 localhost")
    (utils/await-flag was-run)
    (test/is (utils/flag-set? was-run))
    (sniffer/stop-sniffer sniffer)
    (sniffer/stop-forwarder forwarder)))
