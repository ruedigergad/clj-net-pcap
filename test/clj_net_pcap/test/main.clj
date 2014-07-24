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
  (let [out-string (with-out-str (-main "-i" "lo" "-d" "1" "-f" "less 1"))]
    (println "Example app output follows:\n" out-string)))

(deftest test-simple-manual-main-run
  (let [out-string (with-in-str "q" (with-out-str (-main "-i" "lo" "-f" "less 1")))]
    (println "Example app output follows:\n" out-string)))

