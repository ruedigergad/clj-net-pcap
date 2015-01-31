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
