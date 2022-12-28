;;;
;;; Copyright (C) 2012-2022 Ruediger Gad
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
    :doc "Functions for handling functionality related to org.jnetpcap.Pcap
          such as listing network devices, creating and setting filters, or 
          creating, starting, and stopping an pcap instance."} 
  clj-net-pcap.pcap
  (:require (clj-assorted-utils [util :as utils]))
  (:require (clojure [string :as string]))
  #_{:clj-kondo/ignore [:use]}
  (:use clj-net-pcap.native)
  (:import (java.util ArrayList) 
           (org.jnetpcap Pcap PcapBpfProgram PcapStat)))


(def ^:dynamic *buffer-size* (int (Math/pow 2 26)))
(def ^:dynamic *flags* Pcap/MODE_PROMISCUOUS)
(def ^:dynamic *snap-len* 0x00080)



(defn get-devices
  "Returns a vector containing all network devices found by Pcap or nil if an
   error occured."
  []
  (let [devs (ArrayList.)
        err (StringBuilder.)]
    (if (= (Pcap/findAllDevs devs err) Pcap/OK)
      (vec devs)
      (let [errmsg (str "An error occured while querying available devices:" (str err))]
        (utils/println-err errmsg)
        (throw (RuntimeException. errmsg))))))

(defn get-device
  "Returns the network device with the supplied dev-name or nil if the device 
   does not exist."
  [dev-name]
  (some #(when (= (.getName %1) dev-name) %1) (get-devices)))

(defn device-exists?
  "Convenience function for checking if the device with dev-name exists."
  [dev-name]
  (not (nil? (get-device dev-name))))

(defn print-devices
  "Print information about available devices to stderr."
  []
  (utils/println-err "Available devices are:")
  (doseq [dev (get-devices)]
    (utils/println-err (.getName dev))
    (utils/println-err (str "  " dev))))

(when (utils/is-os? "windows")
  (print-devices))

(def lo (cond
          (device-exists? "lo") "lo"
          (device-exists? "lo0") "lo0"
          :else (let [lo-devs (filter #(string/includes? (string/lower-case (.getDescription %1)) "loopback") (get-devices))]
                  (if (not (empty? lo-devs))
                    (let [lo-dev (first lo-devs)]
                      (utils/println-err "Using the following device as loopback:")
                      (utils/println-err (str "  " lo-dev))
                      (.getName lo-dev))
                    (do
                      (utils/println-err "Warning: Could not find name for loopback device.")
                      (print-devices))))))
(def any "any")
(def first-wired-dev
  "This is a somewhat approximation to get the first wired network device.
   At the time of writing, this should be something like:
   eth0 (historic default on many Linux distributions),
   em0 (default on FreeBSD), or en* (CentOS, e.g., uses this naming scheme.).
   However, this approximation may not be correct."
  (->>
   (get-devices)
   (filter #(> (count (.getAddresses %)) 0))
   (map #(.getName %))
   sort
   (remove #(= % lo))
   (remove #(string/starts-with? % "w"))
   first))



(defn create-online-pcap
  "Creates a Pcap instance and initializes it with the values for:
   *buffer-size*, *flags*, *snap-len*. You can \"override\" the default values
   by \"re-binding\" those vars.
   Please note: *flags* is currently only passed to Pcap.setPromisc()."
  [dev-name]
  (when (not (device-exists? dev-name))
    (let [errmsg (str "Error creating online pcap. Device " dev-name " does not exist.")]
      (utils/println-err errmsg)
      (throw (RuntimeException. errmsg))))
  (let [err (StringBuilder.)
        _ (utils/println-err "Creating pcap with: device =" dev-name
                       "; buffer size =" *buffer-size*
                       "; snaplen =" *snap-len*
                       "; and promiscuous mode (flags) =" *flags*)
        pcap (doto (Pcap/create dev-name err)
               (.setBufferSize *buffer-size*)
               (.setPromisc *flags*)
               (.setSnaplen *snap-len*))]
    (when (not (utils/is-os? "windows"))
      (.setImmediateMode pcap 1))
    (if (nil? pcap)
      (let [errmsg (str "An error occured while creating a pcap instance: " (str err))]
        (utils/println-err errmsg)
        (throw (RuntimeException. errmsg)))
      pcap)))

(defn activate-online-pcap
  "Activates the passed Pcap instance."
  [^Pcap pcap]
  (if (= (.activate pcap) Pcap/OK)
    pcap
    (let [errmsg (str "Error activating pcap: " (.getErr pcap))]
      (utils/println-err errmsg)
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
        (utils/println-err "Error compiling pcap filter: " (.getErr pcap))))))

(defn set-filter
  "Sets the given filter f for the given Pcap instance pcap."
  [^Pcap pcap f]
  (when (not= (.setFilter pcap f) Pcap/OK)
    (let [errmsg (str "Error setting pcap filter: " (.getErr pcap))]
      (utils/println-err errmsg)
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
                  (cond
                    (and (utils/is-os? "freebsd") (= dev-name lo))
                      (.inject pcap (byte-array (map byte (concat [2 0 0 0] (repeat 128 0)))))
                    :else
                      (.inject pcap (byte-array 128 (byte 0))))
                  (.join @pcap-thread)
                  (.close pcap)
                  (dosync ref-set pcap-thread nil))
          (throw (RuntimeException. (str "Unsupported operation for online pcap: " k)))))
      ([k arg]
        (condp = k
          :send-bytes-packet (.sendPacket ^Pcap pcap ^bytes arg)
          :start (let [run-fn (fn []
                                (println "Starting pcap loop...")
                                (.loop pcap Pcap/LOOP_INFINITE arg nil)
                                (println "Leaving pcap loop..."))]
                   (dosync (ref-set pcap-thread (doto (Thread. run-fn) (.setName "PcapOnlineCaptureThread") (.setDaemon true) (.start)))))
          (throw (RuntimeException. (str "Unsupported operation for online pcap: " k " argument: " arg)))))
      ([k bulk-size use-intermediate-buffer handler]
        (condp = k
          :start (let [snap-len *snap-len*
                       run-fn (fn []
                                (println "Starting pcap loop in bulk operation. Bulksize:" bulk-size " Snap-len:" snap-len)
                                (if use-intermediate-buffer
                                  (.loop pcap Pcap/LOOP_INFINITE bulk-size 
                                         snap-len true handler nil)
                                  (.loop_direct pcap Pcap/LOOP_INFINITE bulk-size 
                                         snap-len true handler nil))
                                (println "Leaving pcap loop..."))]
                   (dosync (ref-set pcap-thread (doto (Thread. run-fn) (.setName "PcapOnlineCaptureThread") (.start)))))
          (throw (RuntimeException. (str "Unsupported operation for online pcap: " k " arguments: " [bulk-size use-intermediate-buffer handler]))))))))

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
        (utils/print-err-ln (.getErr pcap))))))

(defn create-pcap-from-file
  "Create an offline org.jnetpcap.Pcap from a file."
  [file-name]
  (let [err (StringBuilder.)
        pcap (Pcap/openOffline file-name err)]
    (if (nil? pcap)
      (let [errmsg (str "An error occured while opening the offline pcap file:" (str err))]
        (utils/println-err errmsg)
        (throw (RuntimeException. errmsg)))
      pcap)))

#_{:clj-kondo/ignore [:unused-binding]}
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
          :start (let [run-fn (fn [] (.dispatch pcap -1 opt nil))]
                   (doto (Thread. run-fn) (.setName "PcapOfflineCaptureThread") (.setDaemon true) (.start) (.join)))
          (println "Unsupported operation for online pcap:" k))))))
