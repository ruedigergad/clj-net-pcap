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
    :doc "Clojure jNetPcap wrapper tests"} 
  clj-net-pcap.test.pcap
  (:use clojure.test
        clj-net-pcap.pcap))

(deftest test-get-devices
  (let [devices (get-devices)]
    (is (vector? devices)
        "A value of nil indicates an error during the call to jnetpcap.")
    (is (> (count devices) 0) 
        (str "Running this test as a user that does not have the privileges to "
             "list the network interface will cause this test to fail. So, "
             "please make sure you have the right permissions to list the "
             "network interfaces."))))

(deftest test-get-device
  (let [dev (get-device lo)]
    (is (= (type dev) org.jnetpcap.PcapIf))
    (is (= (.getName dev) lo))))

(deftest test-device-exists
  (let [dev lo]
    (is (device-exists? dev))))

(deftest test-create-online-pcap
  (let [pcap (create-online-pcap lo)]
    (is (= org.jnetpcap.Pcap (type pcap)))))

(deftest test-create-and-activate-online-pcap
  (let [pcap (create-and-activate-online-pcap lo)]
    (is (= org.jnetpcap.Pcap (type pcap)))
    (close-pcap pcap)))

(deftest test-create-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (create-and-activate-online-pcap lo)
        f (create-filter pcap filter-string)]
    (is (= org.jnetpcap.PcapBpfProgram (type f)))
    (close-pcap pcap)))

(deftest test-set-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (create-and-activate-online-pcap lo)
        f (create-filter pcap filter-string)]
    (set-filter pcap f)
    (close-pcap pcap)))

(deftest test-create-and-set-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (create-and-activate-online-pcap lo)]
    (create-and-set-filter pcap filter-string)))

(deftest test-create-get-stat-fn
  (let [pcap (create-and-activate-online-pcap lo)
        stat-fn (create-stat-fn pcap)]
    (is (not (nil? stat-fn)))
    (is (not (nil? (stat-fn))))
    (println (stat-fn)
    (close-pcap pcap))))
