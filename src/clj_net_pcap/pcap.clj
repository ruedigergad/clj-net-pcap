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
  (:use clj-assorted-utils.util
        clj-net-pcap.native)
  (:import (java.util ArrayList) 
           (org.jnetpcap Pcap PcapBpfProgram PcapIf PcapStat)))


(def ^:dynamic *buffer-size* (int (Math/pow 2 26)))
(def ^:dynamic *flags* Pcap/MODE_PROMISCUOUS)
(def ^:dynamic *snap-len* 0x00080)


(def lo "lo")
(def any "any")


(defn get-devices
  "Returns a vector containing all network devices found by Pcap or nil if an
   error occured."
  []
  (let [devs (ArrayList.)
        err (StringBuilder.)]
    (if (= (Pcap/findAllDevs devs err) Pcap/OK)
      (vec devs)
      (let [errmsg (str "An error occured while querying available devices:" (str err))]
        (println-err errmsg)
        (throw (RuntimeException. errmsg))))))

(defn get-device
  "Returns the network device with the supplied dev-name or nil if the device 
   does not exist."
  [dev-name]
  (some #(if (= (.getName %1) dev-name) %1) (get-devices)))

(defn device-exists?
  "Convenience function for checking if the device with dev-name exists."
  [dev-name]
  (not (nil? (get-device dev-name))))

(defn create-online-pcap
  "Creates a Pcap instance and initializes it with the values for:
   *buffer-size*, *flags*, *snap-len*. You can \"override\" the default values
   by \"re-binding\" those vars.
   Please note: *flags* is currently only passed to Pcap.setPromisc()."
  [dev-name]
  (let [err (StringBuilder.)
        _ (println-err "Creating pcap with: buffer size =" *buffer-size*
                       "; snaplen =" *snap-len*
                       "; and promiscuous mode (flags) = " *flags*)
        pcap (doto (Pcap/create dev-name err)
               (.setBufferSize *buffer-size*)
               (.setPromisc *flags*)
               (.setSnaplen *snap-len*))]
    (if (nil? pcap)
      (let [errmsg (str "An error occured while creating a pcap instance: " (str err))]
        (println-err errmsg)
        (throw (RuntimeException. errmsg)))
      pcap)))

(defn activate-online-pcap
  "Activates the passed Pcap instance."
  [^Pcap pcap]
  (if (= (.activate pcap) Pcap/OK)
    pcap
    (let [errmsg (str "Error activating pcap: " (.getErr pcap))]
      (println-err errmsg)
      (throw (RuntimeException. errmsg)))))

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
        (= (.compile ^Pcap pcap f filter-string optimize netmask) Pcap/OK)
        f
        ;;; TODO: Should we throw an exception when something went wrong or is 
        ;;;       returning nil sufficient?
        (println-err "Error compiling pcap filter: " (.getErr pcap))))))

(defn set-filter
  "Sets the given filter f for the given Pcap instance pcap."
  [^Pcap pcap f]
  (when (not= (.setFilter pcap f) Pcap/OK)
    (let [errmsg (str "Error setting pcap filter: " (.getErr pcap))]
      (println-err errmsg)
      (throw (RuntimeException. errmsg)))))

(defn create-and-set-filter
  "Convenience function for creating and setting a filter in one step.
   For details see create-filter and set-filter."
  [pcap filter-string]
  (let [f (create-filter (pcap) filter-string)]
    (set-filter (pcap) f)))

(defn create-and-activate-online-pcap
  "Convenience function for creating and activating a Pcap instance in one step.
   See create-online-pcap and activate-online-pcap for details."
  [dev-name]
  (let [pcap (create-online-pcap dev-name)
        pcap-thread (ref nil)]
    (activate-online-pcap pcap)
    (fn
      ([]
        pcap)
      ([k]
        (condp = k
          :stop (do 
                  (println "Stopping online pcap.")
                  (.breakloop pcap)
               ;;; The jNetPcap capture loop may still be active and process
               ;;; at least one packet even after calling Pcap.breakloop().
               ;;; To force the termination of the loop we inject a single dummy
               ;;; packet. To ensure this packet is not filtered by some 
               ;;; previously set filter the filter is explicitly set to accept
               ;;; all packets. See also the jNetPcap docs for more information
               ;;; about the behavior of Pcap.breakloop().
                  (create-and-set-filter (fn [] pcap) "")
                  (.inject pcap (byte-array 1 (byte 0)))
                  (.join @pcap-thread)
                  (dosync ref-set pcap-thread nil)
                  (.close pcap))
          (println "Unsupported operation for online pcap:" k)))
      ([k opt]
        (condp = k
          :start (let [run-fn (fn [] 
                                (.loop pcap Pcap/LOOP_INFINITE opt nil))]
                   (dosync (ref-set pcap-thread (doto (Thread. run-fn) (.setName "PcapOnlineCaptureThread") (.start)))))
          (println "Unsupported operation for online pcap:" k))))))

(defn close-pcap
  "Closes the given Pcap instance."
  [pcap]
  (.close (pcap)))

(defn create-stats-fn
  "Returns an fn that prints statistical data about a org.jnetpcap.Pcap instance.
   Argument is the org.jnetpcap.Pcap instance."
  [pcap]
  (let [pcap-stats (PcapStat.)]
    (fn []
      (if (= 0 (.stats ^Pcap (pcap) pcap-stats))
        {"recv" (.getRecv pcap-stats) 
         "drop" (.getDrop pcap-stats) 
         "ifdrop" (.getIfDrop pcap-stats)}
        (print-err-ln (.getErr pcap))))))

(defn create-pcap-from-file
  "Create an offline org.jnetpcap.Pcap from a file."
  [file-name]
  (let [err (StringBuilder.)
        pcap (Pcap/openOffline file-name err)]
    (if (nil? pcap)
      (let [errmsg (str "An error occured while opening the offline pcap file:" (str err))]
        (println-err errmsg)
        (throw (RuntimeException. errmsg)))
      pcap)))

(defn create-offline-pcap
  "Convenience function for creating and activating a Pcap instance in one step.
   See create-online-pcap and activate-online-pcap for details."
  [file-name]
  (let [pcap (create-pcap-from-file file-name)]
    (fn
      ([]
        pcap)
      ([k])
      ([k opt]
        (condp = k
          :start (let [run-fn (fn [] 
                                (.dispatch pcap -1 opt nil))]
                   (doto (Thread. run-fn) (.setName "PcapOfflineCaptureThread") (.start) (.join)))
          (println "Unsupported operation for online pcap:" k))))))

