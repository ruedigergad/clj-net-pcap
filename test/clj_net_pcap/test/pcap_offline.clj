;;;
;;; Copyright (C) 2013 Ruediger Gad
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
  clj-net-pcap.test.pcap-offline
  (:use clojure.test
        clj-net-pcap.pcap))

(deftest test-create-pcap-from-file-error
  (let [pcap (create-pcap-from-file "this.file.does-not-exist")]
    (is (nil? pcap))))

(deftest test-create-pcap-from-file
  (let [pcap (create-pcap-from-file "offline-test.pcap")]
    (is (not (nil? pcap)))))

