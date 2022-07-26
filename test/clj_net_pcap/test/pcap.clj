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
  (:require
   (clojure [test :as test])
   (clj-net-pcap [pcap :as pcap])))

(def non-existant-pcap-device "non-existant-device-foo")

(test/deftest test-get-devices
  (let [devices (pcap/get-devices)]
    (test/is (vector? devices)
        "A value of nil indicates an error during the call to jnetpcap.")
    (test/is (> (count devices) 0)
        (str "Running this test as a user that does not have the privileges to "
             "list the network interface will cause this test to fail. So, "
             "please make sure you have the right permissions to list the "
             "network interfaces."))))

(test/deftest test-get-device
  (let [dev (pcap/get-device pcap/lo)]
    (test/is (= (type dev) org.jnetpcap.PcapIf))
    (test/is (= (.getName dev) pcap/lo))))

(test/deftest test-device-exists
  (test/is (pcap/device-exists? pcap/lo)))

(test/deftest test-device-does-not-exist
  (test/is (not (pcap/device-exists? non-existant-pcap-device))))

(test/deftest test-create-online-pcap
  (let [pcap (pcap/create-online-pcap pcap/lo)]
    (test/is (= org.jnetpcap.Pcap (type pcap)))))

(test/deftest test-activate-online-pcap-exception
  (println "Please note that this test is supposed to print an error message like: \"Error creating online pcap. ...\"")
  (test/is (thrown-with-msg? RuntimeException #"Error creating online pcap. Device .* does not exist."
                        (pcap/create-online-pcap non-existant-pcap-device))))

(test/deftest test-create-and-activate-online-pcap
  (let [pcap (pcap/create-and-activate-online-pcap pcap/lo)]
    (test/is (= org.jnetpcap.Pcap (type (pcap))))
    (pcap/close-pcap pcap)))

(test/deftest test-create-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (pcap/create-and-activate-online-pcap pcap/lo)
        f (pcap/create-filter (pcap) filter-string)]
    (test/is (= org.jnetpcap.PcapBpfProgram (type f)))
    (pcap/close-pcap pcap)))

(test/deftest test-set-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (pcap/create-and-activate-online-pcap pcap/lo)
        f (pcap/create-filter (pcap) filter-string)]
    (pcap/set-filter (pcap) f)
    (pcap/close-pcap pcap)))

(test/deftest test-create-and-set-filter
  (let [filter-string "tcp[tcpflags] & tcp-syn != 0"
        pcap (pcap/create-and-activate-online-pcap pcap/lo)]
    (pcap/create-and-set-filter pcap filter-string)))

(test/deftest test-create-get-stat-fn
  (let [pcap (pcap/create-and-activate-online-pcap pcap/lo)
        stats-fn (pcap/create-stats-fn pcap)]
    (test/is (not (nil? stats-fn)))
    (test/is (not (nil? (stats-fn))))
    (println (stats-fn))
    (pcap/close-pcap pcap)))

(test/deftest throw-exception-on-invalid-operation-no-arg-test
  (let [pcap (pcap/create-and-activate-online-pcap pcap/lo)]
    (test/is (thrown-with-msg? RuntimeException #"Unsupported operation for online pcap: :this-operation-does-not-exist" (pcap :this-operation-does-not-exist)))
    (pcap/close-pcap pcap)))

(test/deftest throw-exception-on-invalid-operation-single-arg-test
  (let [pcap (pcap/create-and-activate-online-pcap pcap/lo)]
    (test/is (thrown-with-msg? RuntimeException #"Unsupported operation for online pcap: :this-operation-does-not-exist argument: 123" (pcap :this-operation-does-not-exist 123)))
    (pcap/close-pcap pcap)))

(test/deftest throw-exception-on-invalid-operation-three-args-test
  (let [pcap (pcap/create-and-activate-online-pcap pcap/lo)]
    (test/is (thrown-with-msg? RuntimeException #"Unsupported operation for online pcap: :this-operation-does-not-exist arguments: .*" (pcap :this-operation-does-not-exist 123 "blub" :foo)))
    (pcap/close-pcap pcap)))
