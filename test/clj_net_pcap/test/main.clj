;;;
;;; Copyright (C) 2014 Ruediger Gad
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
    :doc "Tests for clj-net-pcap example application main class and method"}
  clj-net-pcap.test.main
  (:use clojure.test
        clj-net-pcap.main
        clj-assorted-utils.util))

(deftest test-simple-timed-main-run
  (let [out-string (with-out-str (-main "-i" "lo" "-d" "2" "-s" "200" "-f" "less 1"))]
    (println "Example app output follows:\n" out-string)))

(deftest test-simple-manual-main-run
  (let [out-string (with-in-str "q" (with-out-str (-main "-i" "lo" "-f" "less 1")))]
    (println "Example app output follows:\n" out-string)))

(deftest test-main-print-help
  (let [out-string (with-out-str (-main "--help"))]
    (println "Example app output follows:\n" out-string)))

(deftest test-manual-main-run-command-interaction
  (let [out-string (with-in-str (str "gf\n"
                                     "af less 1\n"
                                     "gf\n"
                                     "rlf\n"
                                     "gf\n"
                                     "invalid-command\n"
                                     "af less 2\n"
                                     "af or less 3\n"
                                     "gf\n"
                                     "replace-filter or less 3 with-filter or less 4\n"
                                     "gf\n"
                                     "raf\n"
                                     "gf\n"
                                     "af invalid-pcap-filter foo\n"
                                     "gf\n"
                                     "q")
                     (with-out-str (-main "-i" "lo" "-f" "")))]
    (println "Example app output follows:\n" out-string)))

(deftest test-simple-main-read-file
  (let [out-string (with-in-str "q" (with-out-str (-main "-R" "test/clj_net_pcap/test/data/offline-test.pcap")))]
    (println "Example app output follows:\n" out-string)))

(deftest test-simple-timed-main-run-with-no-op-counter-forwarder
  (let [out-string (with-out-str (-main "-i" "lo" "-d" "2" "-f" "less 1" "-F" "counting-no-op-forwarder-fn"))]
    (println "Example app output follows:\n" out-string)))

(deftest test-simple-timed-main-run-with-no-op-calls-per-second-forwarder
  (let [out-string (with-out-str (-main "-i" "lo" "-d" "2" "-f" "less 1" "-F" "calls-per-second-no-op-forwarder-fn"))]
    (println "Example app output follows:\n" out-string)))

(deftest test-simple-timed-main-run-with-combined-output
  (let [_ (exec "ping -c 3 localhost")
        out-string (with-out-str (-main "-i" "lo" "-d" "2" "-f" "icmp" "-T" "pcap-packet-to-no-op" "-F" "stdout-combined-forwarder-fn"))]
    (println "Example app output follows:\n" out-string)))

(deftest test-simple-timed-main-run-with-byte-array-output
  (let [_ (exec "ping -c 3 localhost")
        out-string (with-out-str (-main "-i" "lo" "-d" "2" "-f" "icmp" "-T" "pcap-packet-to-no-op" "-F" "stdout-byte-array-forwarder-fn"))]
    (println "Example app output follows:\n" out-string)))
