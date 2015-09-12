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
    :doc "Clojure jNetPcap wrapper tests"} 
  clj-net-pcap.test.pcap
  (:use clojure.test
        clj-net-pcap.pcap))

(def non-existant-pcap-device "non-existant-device-foo")

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
  (is (device-exists? lo)))

(deftest test-device-does-not-exist
  (is (not (device-exists? non-existant-pcap-device))))

(deftest test-create-online-pcap
  (let [pcap (create-online-pcap lo)]
    (is (= org.jnetpcap.Pcap (type pcap)))))

(deftest test-activate-online-pcap-exception
  (println "Please note that this test is supposed to print an error message like: \"Error creating online pcap. ...\"")
  (is (thrown-with-msg? RuntimeException #"Error creating online pcap. Device .* does not exist."
                        (create-online-pcap non-existant-pcap-device))))

(deftest test-create-and-activate-online-pcap
  (let [pcap (create-and-activate-online-pcap lo)]
    (is (= org.jnetpcap.Pcap (type (pcap))))
    (close-pcap pcap)))

(deftest test-create-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (create-and-activate-online-pcap lo)
        f (create-filter (pcap) filter-string)]
    (is (= org.jnetpcap.PcapBpfProgram (type f)))
    (close-pcap pcap)))

(deftest test-set-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (create-and-activate-online-pcap lo)
        f (create-filter (pcap) filter-string)]
    (set-filter (pcap) f)
    (close-pcap pcap)))

(deftest test-create-and-set-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (create-and-activate-online-pcap lo)]
    (create-and-set-filter pcap filter-string)))

(deftest test-create-get-stat-fn
  (let [pcap (create-and-activate-online-pcap lo)
        stats-fn (create-stats-fn pcap)]
    (is (not (nil? stats-fn)))
    (is (not (nil? (stats-fn))))
    (println (stats-fn))
    (close-pcap pcap)))

(deftest throw-exception-on-invalid-operation-no-arg-test
  (let [pcap (create-and-activate-online-pcap lo)]
    (is (thrown-with-msg? RuntimeException #"Unsupported operation for online pcap: :this-operation-does-not-exist" (pcap :this-operation-does-not-exist)))
    (close-pcap pcap)))

(deftest throw-exception-on-invalid-operation-single-arg-test
  (let [pcap (create-and-activate-online-pcap lo)]
    (is (thrown-with-msg? RuntimeException #"Unsupported operation for online pcap: :this-operation-does-not-exist argument: 123" (pcap :this-operation-does-not-exist 123)))
    (close-pcap pcap)))

(deftest throw-exception-on-invalid-operation-three-args-test
  (let [pcap (create-and-activate-online-pcap lo)]
    (is (thrown-with-msg? RuntimeException #"Unsupported operation for online pcap: :this-operation-does-not-exist arguments: .*" (pcap :this-operation-does-not-exist 123 "blub" :foo)))
    (close-pcap pcap)))

