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
    :doc "A simple proof of concept for adjusting DSL statements with self-adaptivity."}
  clj-net-pcap.self-adaptive-dsl-adjustment
  (:use clojure.pprint
        clj-assorted-utils.util))

(defn create-stat-delta-counter
  []
  (let [delta-cntr (delta-counter)]
    (doseq [e {"out-dropped" 0, "ifdrop" 0, "out-queued" 0, "drop" 0, "recv" 0, "forwarder-failed" 0}]
      (delta-cntr (keyword (key e)) (val e)))
    (fn [current-stats]
      (reduce #(let [k (key %2)]
                 (assoc %1 k (delta-cntr (keyword k) (val %2)))) {} current-stats))))

(defn get-dropped-sum
  [data]
  (let [{:strs [out-dropped ifdrop drop]} data]
    (+ out-dropped ifdrop drop)))

(defn create-repetition-detector
  [repetitions]
  (let [cntr (counter)]
    (fn [pred-f]
      (if (>= (cntr) repetitions)
        (cntr (fn [_] 0)))
      (if (pred-f)
        (cntr inc)
        (cntr (fn [_] 0)))
      (= repetitions (cntr)))))

(defn create-moving-average-calculator
  [cnt]
  (let [data (ref (vec (repeat cnt 0)))]
    (fn
      ([]
        (/ (apply + @data) cnt))
      ([value]
        (dosync (alter data (fn [d v] (-> d (subvec 1) (conj v))) value))))))

(defn create-max-capture-rate-determinator
  [threshold interpolation]
  (let [stats-delta-cntr (create-stat-delta-counter)
        rep-det (create-repetition-detector interpolation)
        mvg-avg-calc (create-moving-average-calculator interpolation)]
    (fn
      [stat-data]
      (let [deltas (stats-delta-cntr stat-data)
            dropped (get-dropped-sum deltas)
            recvd (deltas "recv")]
        (mvg-avg-calc (- recvd dropped))
        (if (rep-det #(> dropped (* recvd threshold)))
          (mvg-avg-calc)
          -1)))))

(defn create-self-adaptation-controller
  [init dynamic-dsl threshold interpolation inactivity]
  (let [state-map (ref {1 {:dsl init :max-cap-rate -1}})
        current-state (ref 1)
        max-cap-rate-det (create-max-capture-rate-determinator threshold interpolation)]
    (swap! dynamic-dsl (fn [_] init))
    (fn
      [stat-data]
      (println "State:" @current-state "State map:" @state-map)
      (if (> 0 (get-in @state-map [@current-state :max-cap-rate]))
        (let [cur-max-cap-rate (max-cap-rate-det stat-data)]
          (println "Determined max. capture rate:" cur-max-cap-rate)
          (when (< 0 cur-max-cap-rate)
            (println "Adjusting max. capture rate for current state.")
            (dosync
              (alter state-map (fn [m] (-> m
                                         (assoc-in [@current-state :max-cap-rate] cur-max-cap-rate)
                                         (assoc (inc @current-state) {:dsl (subvec (get-in m [@current-state :dsl]) 1) :max-cap-rate -1})))))
            (dosync (alter current-state inc))
            (swap! dynamic-dsl (fn [_] (get-in @state-map [@current-state :dsl])))))))))

