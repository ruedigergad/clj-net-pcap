;;;
;;; Copyright (C) 2015 Ruediger Gad
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
        drp-mvg-avg-calc (create-moving-average-calculator interpolation)
        rcv-mvg-avg-calc (create-moving-average-calculator interpolation)]
    (fn
      [stat-data]
      (let [deltas (stats-delta-cntr stat-data)
;            _ (println "deltas:" deltas)
            dropped (get-dropped-sum deltas)
            _ (rcv-mvg-avg-calc (deltas "recv"))
            rcv (rcv-mvg-avg-calc)
            _ (drp-mvg-avg-calc dropped)
            drp (drp-mvg-avg-calc)]
        (if (rep-det #(> dropped 0))
          (* (- 1.0 threshold) rcv)
          -1)))))

(defn create-self-adaptation-controller
  ([init dynamic-dsl threshold interpolation inactivity]
    (create-self-adaptation-controller init dynamic-dsl threshold interpolation inactivity false))
  ([init dynamic-dsl threshold interpolation inactivity localhost]
    (let [state-map (ref {1 {:dsl init :max-cap-rate -1}})
          current-state (ref 1)
          max-cap-rate-det (create-max-capture-rate-determinator threshold interpolation)
          inact-ctr (counter)
          reset-inact (fn []
                        (println "Resetting inact-ctr to" inactivity)
                        (inact-ctr (fn [_] inactivity)))
          stat-delta-cntr (create-stat-delta-counter)]
      (reset! dynamic-dsl init)
      (add-watch current-state :dyn-dsl-update-watch
                 (fn [k r old-state new-state]
                   (println "self-adaptivity-controller state changed from" old-state "to" new-state)
                   (reset! dynamic-dsl (get-in @state-map [new-state :dsl]))
                   (reset-inact)))
      (fn
        [stat-data]
;        (println "State:" @current-state "State map:" @state-map)
        (let [s-data (if localhost
                       (update-in stat-data ["recv"] * 0.5)
                       stat-data)
              deltas (stat-delta-cntr s-data)
              cur-max-cap-rate (double (max-cap-rate-det s-data))]
            (cond
              (< 0 (inact-ctr)) (do
;                                  (println "Decrementing inact-ctr:" (inact-ctr))
                                  (inact-ctr dec))
              (and
                (< 0 (get-dropped-sum deltas))
                ;  ^- TODO: Is zero here OK? Do we need this additional check at all?
                (> 0 (get-in @state-map [@current-state :max-cap-rate])))
                      (do
                        (println "Determined max. capture rate:" cur-max-cap-rate)
                        (when (< 0 cur-max-cap-rate)
                          (println "Adjusting max. capture rate for current state.")
                          (dosync
                            (alter state-map (fn [m] (-> m
                                                       (assoc-in [@current-state :max-cap-rate] cur-max-cap-rate)
                                                       (assoc (inc @current-state) {:dsl (subvec (get-in m [@current-state :dsl]) 1) :max-cap-rate -1})))))
                          (println @state-map)
                          (dosync (alter current-state inc))))
              (and
                (< 1 @current-state)
                (< (deltas "recv") (* (- 1.0 threshold) (get-in @state-map [(dec @current-state) :max-cap-rate]))))
                      (do
                        (println "Restoring DSL for state:" (dec @current-state))
                        (dosync (alter current-state dec)))
              (and
                (< 1 (count (get-in @state-map [@current-state :dsl])))
                (contains? @state-map (inc @current-state))
                (> (deltas "recv") (get-in @state-map [@current-state :max-cap-rate])))
                      (do
                        (println "Using next simpler DSL sub part:" (inc @current-state))
                        (dosync (alter current-state inc)))
    ;          :default (println "Undefined state in self-adaptation-controller."))))))
              :default nil))))))

