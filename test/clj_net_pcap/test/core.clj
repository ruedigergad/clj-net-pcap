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
    :doc "Tests for clj-net-pcap integration"}  
  clj-net-pcap.test.core
  (:use clojure.test
        clj-net-pcap.core
        clj-assorted-utils.util))

(def receive-delay 1000)

(deftest cljnetpcap-test
  (let [was-run (prepare-flag)
        forwarder-fn (fn [_] (set-flag was-run))
        filter-expression ""
        device "lo"
        cljnetpcap (create-and-start-cljnetpcap forwarder-fn device filter-expression)]
    (Thread/sleep receive-delay)
    (exec-blocking "ping -c 1 localhost")
    (Thread/sleep receive-delay)
    (is (flag-set? was-run))
    (stop-cljnetpcap cljnetpcap)))
