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
  (:import (java.util HashMap Map)))



(defn get-offset
  "Get the offset value for the given DSL expression e.
   If the offset is no numeric value this function tries to resolve the offset by its name.
   If the name is not found, an error message is printed and 0 is returned."
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

(defn get-transformation-fn-ret-type
  "Get the return type of a transformation function transf-fn.
   For determining the type, this function calls trans-fn with a 1530 byte dummy byte-array filled with 0."
  [transf-fn]
  (let [dummy-ba (byte-array 1530 (byte 0))
        ret (transf-fn dummy-ba 0)]
    (type ret)))

(defn get-arff-type-for-transformation-fn
  "Get the ARFF return value type for the given transformation function transf-fn."
  [transf-fn]
  (condp = (get-transformation-fn-ret-type transf-fn)
    java.lang.String "STRING"
    "NUMERIC"))

(defn is-new-dsl?
  [e]
  (vector? e))

(defn resolve-transf-fn
  "Resovle the transofrmation function for the given extraction-rule."
  [e]
  (if (is-new-dsl? e)
    (ns-resolve 'clj-net-pcap.dsl.transformation (symbol (name (first (second e)))))
    (ns-resolve 'clj-net-pcap.dsl.transformation (symbol (name (:transformation e))))))
;  ([e ba ba-offset]
;    (let [expr (second e)
;          f-sym (first expr)
;          f (ns-resolve 'clj-net-pcap.byte-array-extraction-dsl f-sym)
;          pkt-off-sym (second expr)
;          pkt-off (var-get (ns-resolve 'clj-net-pcap.packet-offsets pkt-off-sym))]
;      (println e expr f-sym f pkt-off ba ba-offset)
;      (list f ba (+ ba-offset pkt-off)))))

(defn get-arff-type-header
  "Create the ARFF type header."
  ([dsl]
    (get-arff-type-header dsl resolve-transf-fn get-arff-type-for-transformation-fn))
  ([dsl transf-fn-resolver arff-type-fn]
    (reduce
      (fn [s rule]
        (let [attr-name (name (rule :name))
              arff-type (arff-type-fn (transf-fn-resolver rule))]
          (str s "@ATTRIBUTE " attr-name " " arff-type "\n")))
      ""
      (dsl :rules))))

(defn get-arff-header
  [dsl]
  (str "% Packet Capture\n"
       "% Created with clj-net-pcap:\n"
       "% https://github.com/ruedigergad/clj-net-pcap\n"
       "%\n"
       "@RELATION pcap\n\n"
       (get-arff-type-header dsl)
       "\n@DATA\n"))

(defn create-transf-fn
  [transf-def ba off]
  (into 
    '()
    (reverse
      (reduce
        (fn [v transf-el]
          (cond
            (or
              (keyword? transf-el)
              (symbol? transf-el)) (let [s (symbol (name transf-el))]
                                     (condp not= nil
                                       (ns-resolve 'clojure.core s)
                                         (conj v (ns-resolve 'clojure.core s))
                                       (ns-resolve 'clj-net-pcap.dsl.transformation s)
                                         (conj v (ns-resolve 'clj-net-pcap.dsl.transformation s) 'ba)
                                       (ns-resolve 'clj-net-pcap.packet-offsets s)
                                         (conj v `(+ ~(var-get (ns-resolve 'clj-net-pcap.packet-offsets s)) ~off))
                                       (do
                                         (println "Could not resolve keyword/symbol:" s)
                                         v)))
            (list? transf-el) (conj v (into '() (reverse (create-transf-fn transf-el ba off))))
            :default (conj v transf-el)))
        [] transf-def))))

(defn create-extraction-fn-body-for-java-map-type
  "Create the body of an extraction function that extracts data into a Java map."
  [ba offset rules]
  (reduce
    (fn [v rule]
      (if (is-new-dsl? rule)
        (conj v `(.put
                  ~(name (first rule))
                  ~(create-transf-fn (second rule) ba offset)))
        (conj v `(.put
                   ~(name (:name rule))
                   (~(resolve-transf-fn rule) ~ba (+ ~offset ~(get-offset rule)))))))
    '[doto (java.util.HashMap.)] rules))

(defn create-extraction-fn-body-for-clj-map-type
  "Create the body of an extraction function that extracts data into a Clojure map."
  [ba offset rules]
  (reduce
    (fn [v rule]
      (if (is-new-dsl? rule)
        (conj v `(assoc
                   ~(name (first rule))
                   ~(create-transf-fn (second rule) ba offset)))
        (conj v `(assoc
                   ~(name (:name rule))
                   (~(resolve-transf-fn rule) ~ba (+ ~offset ~(get-offset rule)))))))
    '[-> {}] rules))

(defn create-extraction-fn-body-for-csv-str-type
  "Create the body of an extraction function that extracts data into a CSV String."
  [ba offset rules]
  (let [extracted-strings (reduce
                            (fn [v rule]
                              (if (is-new-dsl? rule)
                                (let [transf-fn (create-transf-fn (second rule) ba offset)
                                      transf-ret-type (get-transformation-fn-ret-type (eval `(fn [~ba ~offset] ~transf-fn)))]
                                  (conj v (if (= java.lang.String transf-ret-type)
                                            `(str "\"" ~transf-fn "\"")
                                            transf-fn)))
                                (let [transf-fn (resolve-transf-fn rule)
                                      transf-ret-type (get-transformation-fn-ret-type transf-fn)]
                                  (conj v (if (= java.lang.String transf-ret-type)
                                            `(str "\"" (~transf-fn ~ba (+ ~offset ~(get-offset rule))) "\"")
                                            `(~transf-fn ~ba (+ ~offset ~(get-offset rule))))))))
                            '[str] rules)
        commas (reduce into [] ["." (repeat (- (count rules) 1) ",") "."])]
    (vec (filter #(not= \. %) (interleave extracted-strings commas)))))

(defn create-extraction-fn-body-for-json-str-type
  "Create the body of an extraction function that extracts data into a JSON String."
  [ba offset rules]
  (let [extracted-strings (conj
                            (reduce
                              (fn [v rule]
                                (if (is-new-dsl? rule)
                                  (let [transf-fn (create-transf-fn (second rule) ba offset)
                                        _ (println transf-fn)
                                        transf-ret-type (get-transformation-fn-ret-type (eval `(fn [~ba ~offset] ~transf-fn)))]
                                    (conj v "\"" (name (first rule)) "\":"
                                            (if (= java.lang.String transf-ret-type)
                                              `(str "\"" ~transf-fn "\"")
                                              transf-fn)))
                                  (let [transf-fn (resolve-transf-fn rule)
                                        transf-ret-type (get-transformation-fn-ret-type transf-fn)]
                                    (conj v "\"" (name (:name rule)) "\":"
                                            (if (= java.lang.String transf-ret-type)
                                              `(str "\"" (~transf-fn ~ba (+ ~offset ~(get-offset rule))) "\"")
                                              `(~transf-fn ~ba (+ ~offset ~(get-offset rule))))))))
                              '[str "{"] rules)
                            "}")
        commas (reduce into [] ["." "." "." "." "." (reduce into [] (repeat (- (count rules) 1) ["," "." "." "."])) "." "."])]
;    (println (interleave extracted-strings commas))
    (vec (filter (fn [x] (and (not= \. x) (not= "." x))) (interleave extracted-strings commas)))))

(defn create-extraction-fn
  "Create an extraction function based on the given dsl-expression."
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

