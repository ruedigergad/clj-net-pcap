;;;
;;; Copyright (C) 2012 Ruediger Gad
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
    :doc "Clojure jNetPcap sniffer tests"}
  clj-net-pcap.test.sniffer
  (:use clojure.test
        clj-net-pcap.pcap
        clj-net-pcap.sniffer
        clj-assorted-utils.util)
  (:import (java.util.concurrent LinkedBlockingQueue)))

(def receive-delay 1000)

(deftest test-sniffer
  (let [was-run (prepare-flag)
        handler-fn (fn [_ _] (set-flag was-run))
        pcap (create-and-activate-pcap lo)
        sniffer (create-and-start-sniffer pcap handler-fn nil)]
    (is (not (flag-set? was-run)))
    (Thread/sleep receive-delay)
    (.inject pcap (byte-array 1 (byte 0)))
    (Thread/sleep receive-delay)
    (is (flag-set? was-run))
    (stop-sniffer sniffer)))

(deftest test-forwarder
  (let [was-run (prepare-flag)
        forwarder-fn (fn [_] (set-flag was-run))
        queue (LinkedBlockingQueue.)
        forwarder (create-and-start-forwarder queue forwarder-fn)]
    (is (not (flag-set? was-run)))
    (.offer queue "foo")
    (Thread/sleep receive-delay)
    (is (flag-set? was-run))
    (stop-forwarder forwarder)))

(deftest sniffer-forwarder-interaction
  (let [was-run (prepare-flag)
        queue (LinkedBlockingQueue.)
        handler-fn (fn [p u] (.offer queue (create-packet p u)))
        forwarder-fn (fn [_] (set-flag was-run))
        forwarder (create-and-start-forwarder queue forwarder-fn)
        pcap (create-and-activate-pcap lo)
        sniffer (create-and-start-sniffer pcap handler-fn)]
    (Thread/sleep receive-delay)
    (exec-blocking "ping -c 1 localhost")
    (Thread/sleep receive-delay)
    (is (flag-set? was-run))
    (stop-sniffer sniffer)
    (stop-forwarder forwarder)))

(deftest sniffer-forwarder-interaction-cloned
  (let [was-run (prepare-flag)
        queue (LinkedBlockingQueue.)
        handler-fn (fn [p _] (.offer queue (clone-packet p)))
        forwarder-fn (fn [_] (set-flag was-run))
        forwarder (create-and-start-forwarder queue forwarder-fn)
        pcap (create-and-activate-pcap lo)
        sniffer (create-and-start-sniffer pcap handler-fn)]
    (Thread/sleep receive-delay)
    (exec-blocking "ping -c 1 localhost")
    (Thread/sleep receive-delay)
    (is (flag-set? was-run))
    (stop-sniffer sniffer)
    (stop-forwarder forwarder)))
