;;;
;;; Copyright (C) 2015 Ruediger Gad
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
    :doc "A simple DSL for extracting data from packets that are represented as byte arrays."}
  clj-net-pcap.byte-array-extraction-dsl
  (:require (clj-net-pcap [packet-offsets :as offsets]))
  (:use clojure.pprint
        clj-assorted-utils.util)
  (:import (java.util HashMap Map)
           (clj_net_pcap ByteArrayHelper)
           (org.jnetpcap.packet.format FormatUtils)))



(defn int16
  [ba idx]
  (ByteArrayHelper/getInt16 ba idx))

(defn put
  [^Map m k v]
  (.put m k v))

(defn create-parse-fn
  [ba]
  (fn [v e]
    (conj v `(.put 
               ~(:name e)
               (~(resolve (symbol (str "clj-net-pcap.byte-array-extraction-dsl/" (:transformation e)))) ~ba ~(:offset e))))))

(defn create-extraction-fn
  [dsl-expression]
  (let [ba-sym 'ba
        _ (println dsl-expression)
        fn-body-vec (reduce (create-parse-fn ba-sym) '[doto (java.util.HashMap.)] dsl-expression)
        _ (println "Created extraction function vector from DSL:" fn-body-vec)
        fn-body (reverse (into '() fn-body-vec))
        extraction-fn (eval `(fn [~ba-sym] ~fn-body))]
    extraction-fn))

