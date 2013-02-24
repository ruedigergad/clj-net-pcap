;;;
;;; Copyright (C) 2012 Ruediger Gad
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
    :doc "Functions for handling functionality related to org.jnetpcap.Pcap
          such as listing network devices, creating and setting filters, or 
          creating, starting, and stopping an pcap instance."} 
  clj-net-pcap.pcap
  (:use clj-assorted-utils.util)
  (:import (java.util ArrayList) 
           (org.jnetpcap Pcap PcapBpfProgram PcapIf PcapStat)))


(def ^:dynamic *buffer-size* (int (Math/pow 2 27)))
(def ^:dynamic *flags* Pcap/MODE_PROMISCUOUS)
(def ^:dynamic *snap-len* 0x10000)


(def lo "lo")
(def any "any")


(defn get-devices []
  "Returns a vector containing all network devices found by Pcap or nil if an
   error occured."
  (let [devs (ArrayList.)
        err (StringBuilder.)]
    (if (= (Pcap/findAllDevs devs err) 0)
      (vec devs)
      ;;; TODO: Should we throw an exception when something went wrong or is 
      ;;;       returning nil sufficient?
      (println (.toString err)))))

(defn get-device [dev-name]
  "Returns the network device with the supplied dev-name or nil if the device 
   does not exist."
  (some #(if (= (.getName %1) dev-name) %1) (get-devices)))

(defn device-exists? [dev-name]
  "Convenience function for checking if the device with dev-name exists."
  (not (nil? (get-device dev-name))))

(defn create-pcap [dev-name]
  "Creates a Pcap instance and initializes it with the values for:
   *buffer-size*, *flags*, *snap-len*. You can \"override\" the default values
   by \"re-binding\" those vars.
   Please note: *flags* is currently only passed to Pcap.setPromisc()."
  (let [err (StringBuilder.)]
    (doto (Pcap/create dev-name err)
      (.setBufferSize *buffer-size*)
      (.setPromisc *flags*)
      (.setSnaplen *snap-len*))))

(defn activate-pcap [^Pcap pcap]
  "Activates the passed Pcap instance."
  (if (= (.activate pcap) Pcap/OK)
    pcap
    (let [errmsg (str "Error activating pcap: " (.getErr pcap))]
      (println errmsg)
      (throw (RuntimeException. errmsg)))))

(defn create-and-activate-pcap [dev-name]
  "Convenience function for creating and activating a Pcap instance in one step.
   See create-pcap and activate-pcap for details."
  (let [pcap (create-pcap dev-name)]
    (activate-pcap pcap)))

(defn close-pcap [pcap]
  "Closes the given Pcap instance."
  (.close pcap))

(defn create-filter
  "Creates and compiles a filter given as String. Optionally the optimize flag
   and netmask can be passed. The default value for optimize is 1 and for 
   netmask is 0."
  ([pcap filter-string]
    (create-filter pcap filter-string 1))
  ([pcap filter-string optimize]
    (create-filter pcap filter-string optimize 0))
  ([pcap filter-string optimize netmask] 
    (let [f (PcapBpfProgram.)]
      (if 
        (= (.compile pcap f filter-string optimize netmask) Pcap/OK)
        f
        ;;; TODO: Should we throw an exception when something went wrong or is 
        ;;;       returning nil sufficient?
        (println "Error compiling pcap filter: " (.getErr pcap))))))

(defn set-filter [pcap f]
  "Sets the given filter f for the given Pcap instance pcap."
  (if (not= (.setFilter pcap f) Pcap/OK)
    (let [errmsg (str "Error setting pcap filter: " (.getErr pcap))]
      (println errmsg)
      (throw (RuntimeException. errmsg)))))

(defn create-and-set-filter [pcap filter-string]
  "Convenience function for creating and setting a filter in one step.
   For details see create-filter and set-filter."
  (let [f (create-filter pcap filter-string)]
    (set-filter pcap f)))

(defn create-stat-fn [pcap]
  (let [pcap-stats (PcapStat.)]
    (fn []
      (if (= 0 (.stats pcap pcap-stats))
        (.toString pcap-stats)
        (print-err-ln (.getErr pcap))))))

(defn create-pcap-from-file [file-name]
  (let [err (StringBuilder.)]
    (Pcap/openOffline file-name err)))

