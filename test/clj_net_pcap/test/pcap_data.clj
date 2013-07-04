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
    :doc "Clojure tests for reading from pcap files."} 
  clj-net-pcap.test.pcap-data
  (:use clojure.test
        clj-net-pcap.native
        clj-net-pcap.pcap-data
        clj-assorted-utils.util))

(deftest test-guess-class-c-net
  (let [ip-addr "192.168.42.123"]
    (is (= :class-c (network-class ip-addr)))
    (is (= "192.168.42.0" (guess-subnet ip-addr)))
    (is (= "255.255.255.0" (guess-subnet-mask ip-addr)))
    (is (= 24 (guess-subnet-mask-bits ip-addr)))))

(deftest test-guess-class-a-net
  (let [ip-addr "10.123.45.67"]
    (is (= :class-c (network-class ip-addr)))
    (is (= "10.0.0.0" (guess-subnet ip-addr)))
    (is (= "255.0.0.0" (guess-subnet-mask ip-addr)))
    (is (= 8 (guess-subnet-mask-bits ip-addr)))))

