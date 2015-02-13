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


(defn int4low
  [ba idx]
  (ByteArrayHelper/getNibbleLow ba idx))

(defn int4high
  [ba idx]
  (ByteArrayHelper/getNibbleHigh ba idx))

(defn int8
  [ba idx]
  (ByteArrayHelper/getByte ba idx))

(defn int16
  [ba idx]
  (ByteArrayHelper/getInt16 ba idx))

(defn int32
  [ba idx]
  (ByteArrayHelper/getInt ba idx))

(defn int32be
  [ba idx]
  (ByteArrayHelper/getIntBigEndian ba idx))

(defn timestamp
  [ba idx]
  (+ (* (ByteArrayHelper/getInt ba idx) 1000000000) (* (ByteArrayHelper/getInt ba (+ idx 4)) 1000)))

(defn timestamp-be
  [ba idx]
  (+ (* (ByteArrayHelper/getIntBigEndian ba idx) 1000000000) (* (ByteArrayHelper/getIntBigEndian ba (+ idx 4)) 1000)))

(defn ethernet-address
  [ba idx]
  (FormatUtils/asStringZeroPad ba \: 16 idx 6))

(defn ipv4-address
  [ba idx]
  (FormatUtils/asString ba \. 10 idx 4))

(defn get-offset
  [e]
  (let [offset-val (:offset e)]
    (cond
      (number? offset-val) offset-val
      (or
        (keyword? offset-val)
        (string? offset-val)) (var-get (resolve (symbol (str "clj-net-pcap.packet-offsets/" (name offset-val)))))
      :default (do
                 (println "Error: Got unknown offset value" offset-val "from entry" e)
                 0))))

(defn create-extraction-fn-body-for-java-map-type
  [ba offset rules]
  (reduce
    (fn [v e]
      (conj v `(.put
                 ~(name (:name e))
                 (~(resolve (symbol (str "clj-net-pcap.byte-array-extraction-dsl/" (name (:transformation e))))) ~ba (+ ~offset ~(get-offset e))))))
    '[doto (java.util.HashMap.)] rules))

(defn create-extraction-fn-body-for-clj-map-type
  [ba offset rules]
  (reduce
    (fn [v e]
      (conj v `(assoc
                 ~(name (:name e))
                 (~(resolve (symbol (str "clj-net-pcap.byte-array-extraction-dsl/" (name (:transformation e))))) ~ba (+ ~offset ~(get-offset e))))))
    '[-> {}] rules))

(defn create-extraction-fn-body-for-csv-str-type
  [ba offset rules]
  (let [extracted-strings (reduce
                            (fn [v e]
                              (conj v `(~(resolve (symbol (str "clj-net-pcap.byte-array-extraction-dsl/" (name (:transformation e))))) ~ba (+ ~offset ~(get-offset e)))))
                            '[str] rules)
        commas (reduce into [] ["." (repeat (- (count rules) 1) ",") "."])]
    (vec (filter #(not= \. %) (interleave extracted-strings commas)))))

(defn create-extraction-fn-body-for-json-str-type
  [ba offset rules]
  (let [extracted-strings (conj
                            (reduce
                              (fn [v e]
                                (conj v "\"" (name (:name e)) "\":"
                                        `(~(resolve (symbol (str "clj-net-pcap.byte-array-extraction-dsl/" (name (:transformation e))))) ~ba (+ ~offset ~(get-offset e)))))
                              '[str "{"] rules)
                            "}")
        commas (reduce into [] ["." "." "." "." "." (reduce into [] (repeat (- (count rules) 1) ["," "." "." "."])) "." "."])]
    (println (interleave extracted-strings commas))
    (vec (filter (fn [x] (and (not= \. x) (not= "." x))) (interleave extracted-strings commas)))))

(defn create-extraction-fn
  [dsl-expression]
;  (println "Got DSL expression:" dsl-expression)
  (let [ba-sym 'ba
        offset-sym 'offset
        fn-body-vec (cond
                      (vector? dsl-expression)
                        (create-extraction-fn-body-for-java-map-type ba-sym offset-sym dsl-expression)
                      (map? dsl-expression)
                        (let [rules (:rules dsl-expression)
                              t (:type dsl-expression)]
                          (condp = (name t)
                            "java-map" (create-extraction-fn-body-for-java-map-type ba-sym offset-sym rules)
                            "clj-map" (create-extraction-fn-body-for-clj-map-type ba-sym offset-sym rules)
                            "csv-str" (create-extraction-fn-body-for-csv-str-type ba-sym offset-sym rules)
                            "json-str" (create-extraction-fn-body-for-json-str-type ba-sym offset-sym rules)
                            (do
                              (println "Unknown type:" t)
                              (println "Defaulting to :java-maps")
                              (create-extraction-fn-body-for-java-map-type ba-sym offset-sym rules))))
                      :default (println "Invalid DSL expression:" dsl-expression))



;        _ (println "Created extraction function vector from DSL:" fn-body-vec)
        fn-body (reverse (into '() fn-body-vec))
;        _ (println "Created extraction function body:" fn-body)
        extraction-fn (eval `(fn [~ba-sym ~offset-sym] ~fn-body))]
    extraction-fn))

(def ipv4-udp-be-dsl-expression
  [{:offset 0 :transformation "timestamp-be" :name "ts"}
   {:offset 12 :transformation "int32be" :name "len"}
   {:offset "eth-dst" :transformation "ethernet-address" :name "ethDst"}
   {:offset "eth-src" :transformation "ethernet-address" :name "ethSrc"}
   {:offset "ipv4-dst" :transformation "ipv4-address" :name "ipDst"}
   {:offset "ipv4-src" :transformation "ipv4-address" :name "ipSrc"}
   {:offset "ipv4-id" :transformation "int16" :name "ipId"}
   {:offset "ipv4-ttl" :transformation "int8" :name "ipTtl"}
   {:offset "ipv4-checksum" :transformation "int16" :name "ipChecksum"}
   {:offset "ipv4-version" :transformation "int4high" :name "ipVer"}
   {:offset "udp-src" :transformation "int16" :name "udpSrc"}
   {:offset "udp-dst" :transformation "int16" :name "udpDst"}])

(def ipv4-udp-le-dsl-expression
  [{:offset 0 :transformation "timestamp" :name "ts"}
   {:offset 12 :transformation "int32" :name "len"}
   {:offset "eth-dst" :transformation "ethernet-address" :name "ethDst"}
   {:offset "eth-src" :transformation "ethernet-address" :name "ethSrc"}
   {:offset "ipv4-dst" :transformation "ipv4-address" :name "ipDst"}
   {:offset "ipv4-src" :transformation "ipv4-address" :name "ipSrc"}
   {:offset "ipv4-id" :transformation "int16" :name "ipId"}
   {:offset "ipv4-ttl" :transformation "int8" :name "ipTtl"}
   {:offset "ipv4-checksum" :transformation "int16" :name "ipChecksum"}
   {:offset "ipv4-version" :transformation "int4high" :name "ipVer"}
   {:offset "udp-src" :transformation "int16" :name "udpSrc"}
   {:offset "udp-dst" :transformation "int16" :name "udpDst"}])

