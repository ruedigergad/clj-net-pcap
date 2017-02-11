;;;
;;; Copyright (C) 2012 Ruediger Gad
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
    :doc "Main class and method for launching a simple clj-net-pcap based sniffer
          that prints some information about the captured packets to stdout.
          This is primarily intended for testing and documentation purposes."}
  clj-net-pcap.main
  (:use cli4clj.cli
        clojure.pprint
        [clojure.string :only [join split]]
        clojure.tools.cli
        clj-net-pcap.byte-array-extraction-dsl
        clj-net-pcap.core
        clj-net-pcap.dsl.transformation
        clj-net-pcap.native
        clj-net-pcap.packet-gen
        clj-net-pcap.pcap-data
        clj-net-pcap.self-adaptive-dsl-adjustment
        clj-assorted-utils.util)
  (:gen-class))

(defn- parse-args [args]
  (cli args
    ["-a" "--self-adaptation"
     "Interval for self-adaptation of DSL expressions in ms."
     :default -1
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-b" "--bulk-size"
     "The bulk size to use."
     :default 1
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-d" "--duration"
     "The duration in seconds how long clj-net-pcap is run."
     :default -1
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-e" "--dsl-expression"
     (str "Configure a DSL expression for extracting data from raw packet data in form of byte arrays."
          "Pre-configured DSL expressions are:\n"
          "ipv4-udp-be-dsl-expression, ipv4-udp-le-dsl-expression")
     :default ""]
    ["-f" "--filter"
     (str "Pcap filter to be used."
          " Defaults to the empty String which means that all packets are captured.")
     :default ""]
    ["-h" "--help" "Print this help." :flag true]
    ["-i" "--interface"
     "Interface on which the packets are captured"
     :default "lo"]
    ["-r" "--raw"
     (str "Emit raw data instead of decoded packets."
          " Be careful, not all transformation and forwarder functions support this.")
     :flag true]
    ["-s" "--stats"
     (str "Print stats to stderr in a regular interval."
          " The interval is given as parameter in milliseconds."
          " Values smaller equal 0 mean that no stats are printed.")
     :default 0
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-t" "--dynamic-transformation-fn"
     (str "If set, the transformation-fn can be changed dynamically at runtime.")
     :flag true]
    ["-w" "--write-to-file"
     "Write output to file with the given name."
     :default nil]
    ["-A" "--self-adaptation-opts"
     "Options for self-adaptive adjustment of DSL expressions."
     :default {:threshold 0.01, :interpolation 2, :inactivity 1}
     :parse-fn #(read-string %)]
    ["-B" "--buffer-size"
     "The buffer size to use."
     :default (int (Math/pow 2 26))
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-D" "--debug" "Enable additional debugging." :flag true]
    ["-F" "--forwarder-fn"
     (str "Use the specified function as forwarder function for processing packets.\n"
          "Available function names are:\n"
          "stdout-combined-forwarder-fn, stdout-byte-array-forwarder-fn, "
          "stdout-forwarder-fn, no-op-converter-forwarder-fn, "
          "counting-no-op-forwarder-fn, calls-per-second-no-op-forwarder-fn")
     :default "stdout-forwarder-fn"]
    ["-S" "--snap-len"
     (str "The snaplen to use."
          " This determines how many bytes of data will be captured from each packet.")
     :default 128
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-T" "--transformation-fn"
     (str "Use the specified function for transforming the raw packets."
          " Available function names are:\n"
          "  pcap-packet-to-bean, pcap-packet-to-map, pcap-packet-to-nested-maps,\n"
          "  pcap-packet-to-bean-ipv4-udp-only, pcap-packet-to-map-ipv4-udp-only,\n"
          "  packet-byte-buffer-extract-map-ipv4-udp-single, packet-byte-buffer-extract-map-ipv4-udp-bulk,\n"
          "  packet-byte-buffer-extract-bean-ipv4-udp-single, packet-byte-buffer-extract-bean-ipv4-udp-bulk, no-op")
     :default "pcap-packet-to-bean"]
    ["-R" "--read-file"
     "Read from a pcap file instead of performing a live capture."
     :default ""]
    ["-W" "--write-arff-header"
     "Prefix write output with ARFF header: http://weka.wikispaces.com/ARFF+%28stable+version%29"
     :flag true]))

(defn -main [& args]
  (let [cli-args (parse-args args)
        arg-map (cli-args 0)
        help-string (cli-args 2)]
    (when (arg-map :help)
      (println help-string)
      (System/exit 0))
    (println "Starting clj-net-pcap using the following options:")
    (pprint arg-map)
    (let [pcap-file-name (arg-map :read-file)
          dsl-expr-string (arg-map :dsl-expression)
          bulk-size (arg-map :bulk-size)
          cap-if (arg-map :interface)
          dsl-expression (let [expr (resolve (symbol (str "clj-net-pcap.byte-array-extraction-dsl/" dsl-expr-string)))]
                           (if expr
                             (var-get expr)
                             (if (not= "" dsl-expr-string)
                               (read-string dsl-expr-string))))
          _ (println "DSL expression from command line args:" dsl-expression)
          get-dsl-fn (fn [dsl-expr]
                       (let [extraction-fn (create-extraction-fn dsl-expr)]
                         (if (> bulk-size 1)
                           (partial process-packet-byte-buffer-bulk extraction-fn)
                           (partial process-packet-byte-buffer extraction-fn))))
          get-transformation-fn (fn []
                                  (if dsl-expression
                                    (get-dsl-fn dsl-expression)
                                    (resolve (symbol (str "clj-net-pcap.pcap-data/" (arg-map :transformation-fn))))))
          static-transformation-fn (get-transformation-fn)
          dynamic-transformation-fn (atom (get-transformation-fn))
          dynamic-dsl-expression (atom nil)
          sa-opts (arg-map :self-adaptation-opts)
          self-adapt-ctrlr (create-self-adaptation-controller dsl-expression dynamic-dsl-expression
                                                              (sa-opts :threshold) (sa-opts :interpolation)
                                                              (sa-opts :inactivity) (= "lo" cap-if))
          _ (add-watch dynamic-dsl-expression :dsl-fn-update-watch
                       (fn [k r old-val new-val]
                         (println "Dynamic DSL updated.")
;                             (println Updating dynamic transformation fn:" new-val)
                         (let [dsl-fn (get-dsl-fn new-val)]
                           (reset! dynamic-transformation-fn dsl-fn))))
          output-file (arg-map :write-to-file)
          file-output-forwarder (when (not (nil? output-file))
                                  (println "Writing data to file:" output-file)
                                  (create-file-out-forwarder output-file
                                                             (> bulk-size 1)
                                                             (if (arg-map :write-arff-header)
                                                               (get-arff-header dsl-expression)
                                                               "")))
          processing-fn (let [f-tmp (resolve (symbol (str "clj-net-pcap.pcap-data/" (arg-map :forwarder-fn))))
                              f (cond
                                  (not (nil? file-output-forwarder)) file-output-forwarder
                                  (= 'packet (first (first (:arglists (meta f-tmp))))) f-tmp
                                  :default (f-tmp bulk-size))]
                          (println "Resolved forwarder fn:" f)
                          (if (arg-map :dynamic-transformation-fn)
                            (do
                              (println "Using dynamic transformation-fn:" @dynamic-transformation-fn)
                              #(let [o (@dynamic-transformation-fn %)]
                                 (if o
                                   (f o))))
                            (do
                              (println "Using static transformation-fn:" static-transformation-fn)
                              #(let [o (static-transformation-fn %)]
                                 (if o
                                   (f o))))))
          cljnetpcap (binding [clj-net-pcap.core/*bulk-size* bulk-size
                               clj-net-pcap.core/*emit-raw-data* (arg-map :raw)
                               clj-net-pcap.core/*forward-exceptions* (arg-map :debug)
                               clj-net-pcap.pcap/*snap-len* (arg-map :snap-len)
                               clj-net-pcap.pcap/*buffer-size* (arg-map :buffer-size)]
                       (if (= "" pcap-file-name)
                         (create-and-start-online-cljnetpcap
                           processing-fn
                           cap-if
                           (arg-map :filter))
                         (process-pcap-file
                           pcap-file-name
                           processing-fn)))
          stat-interval (arg-map :stats)
          stat-out-executor (executor)
          shutdown-fn (fn [] (do
                               (println "clj-net-pcap is shuting down...")
                               (when (> stat-interval 0)
                                 (println "Stopping stat output.")
                                 (shutdown stat-out-executor))
                               (get-stats cljnetpcap)
                               (when (not (nil? file-output-forwarder))
                                 (println "Closing file output forwarder...")
                                 (file-output-forwarder))
                               (stop-cljnetpcap cljnetpcap)
                               (println "Removing temporarily extracted native libs...")
                               (remove-native-libs)))
          run-duration (arg-map :duration)
          sa-interval (arg-map :self-adaptation)
          sa-executor (executor)
          shutdown-timer-executor (executor)]
      (if (not= "" pcap-file-name)
        (println "clj-net-pcap standalone executable started.\n"))
      (when (> stat-interval 0)
        (println "Printing stats to stderr in intervalls of" stat-interval "ms.")
        (run-repeat stat-out-executor #(print-err-ln (get-stats cljnetpcap)) stat-interval))
      (when (> sa-interval 0)
        (println "Enabling self-adaptivity with interval:" sa-interval)
        (run-repeat sa-executor #(self-adapt-ctrlr (get-stats cljnetpcap)) sa-interval))
      (cond
        (not= "" pcap-file-name)
          (do
            (println "Finished reading from pcap file.")
            (sleep stat-interval))
        (> run-duration 0)
          (do
            (println "Will automatically shut down in" run-duration "seconds.")
            (run-once shutdown-timer-executor shutdown-fn (* 1000 run-duration)))
        :default
          (let [cli-opts
                  {:cmds
                    {:add-filter
                      {:fn #(try (add-filter cljnetpcap %)
                              (catch Exception e
                                (println "Error adding filter:" e)
                                (.printStackTrace e)))
                       :short-info "Add a new pcap filter."
                       :long-info (str "Two situations have to be distinguished:\n"
                                        "\tthe initial filter addition and subsequent additions.\n"
                                        "\tE.g. (initial filter): \"af \"tcp\"\"\n"
                                        "\tE.g. (subsequent filter): \"af \"or udp\"\"\n"
                                        "\tNote the \"or\" (also possible \"and\") statement for chaining the filter expressions.")}
                     :af :add-filter
                     :get-filter {:fn #(pprint (get-filters cljnetpcap))
                                  :short-info "Returns the currently active filter(s)."}
                     :gf :get-filter
                     :remove-last-filter {:fn #(remove-last-filter cljnetpcap)
                                          :short-info "Removes the last filter expression."}
                     :rlf :remove-last-filter
                     :remove-all-filters {:fn #(remove-all-filters cljnetpcap)
                                          :short-info "Remove all filter expressions."}
                     :raf :remove-all-filters
                     :replace-filter {:fn #(let [filters (split % #" with-filter ")]
                                             (replace-filter cljnetpcap (first filters) (second filters)))
                                      :short-info "Replace an existing filter with another one."
                                      :long-info "E.g.: replace-filter \"or udp with or icmp\""}
                     :generate-packet
                      {:fn #(println (vec (generate-packet-data %)))
                       :short-info "Generates a vector with raw packet data."
                       :long-info (str "The input is a packet description as clojure map.\n"
                                       "\tE.g.: gp {\"len\" 20, \"ethSrc\" \"01:02:03:04:05:06\", \"ethDst\" \"FF:FE:FD:F2:F1:F0\"}\n"
                                       "\tE.g.: gp {\"len\" 54, \"ethSrc\" \"01:02:03:04:05:06\", \"ethDst\" \"FF:FE:FD:F2:F1:F0\", \"ipVer\" 4, \"ipDst\" \"252.253.254.255\", \"ipId\" 3, \"ipType\" 1, \"ipTtl\" 7, \"ipSrc\" \"1.2.3.4\", \"icmpType\" 8, \"icmpId\" 123, \"icmpSeqNo\" 12, \"data\" \"abcd\"}")}
                     :gp :generate-packet
                     :send-packet
                      {:fn #(if (map? %)
                              (cljnetpcap :send-packet-map %)
                              (cljnetpcap :send-bytes-packet (byte-array (map byte %))))
                       :short-info "Send a generated packet via the current capture device."
                       :long-info (str "The packet to be sent can be either defined as map like shown for \"gen-packet\"\n"
                                       "\tor can be a raw packet data vector like emitted by \"gen-packet\".")}
                     :sp :send-packet
                     :set-dsl-transformation-function
                      {:fn (fn [dsl-definition]
                             (let [new-dsl-def (if (string? dsl-definition)
                                                 (binding [*read-eval* false] (read-string dsl-definition))
                                                 dsl-definition)
                                   new-dsl-t-fn (get-dsl-fn new-dsl-def)]
                               (reset! dynamic-transformation-fn new-dsl-t-fn)))
                       :short-info "Set the transformation function based on the provided DSL expression."
                       :long-info (str "Please note: this requires DSL-based processing\n"
                                       "\tAND the dynamic transformation function to be enabled.\n"
                                       "\tThis means that clj-net-pcap has to be started with at least \"-r -t\" as command line arguments.\n\n"
                                       "\tExamples of expressions are:\n"
                                       "\tsdtf {:type :json-str :rules [[ipV4Src (ipv4-address ipv4-src)] [ipV4Dst (ipv4-address ipv4-dst)]]}\n"
                                       "\tsdtf {:type :json-str :rules [[udpSrc (int16 udp-src)] [udpDst (int16 udp-dst)]]}\n"
                                       "\tsdtf {:type :json-str :rules [[ipV4Src (ipv4-address ipv4-src)] [ipV4Dst (ipv4-address ipv4-dst)] [icmpType (int8 icmp-type)] [icmpCode (int8 icmp-code)] [icmpSeqNo (int16 icmp-seq-no)]]}\n"
                                       "\tsdtf {:type :csv-str :rules [[ipV4Src (ipv4-address ipv4-src)] [ipV4Dst (ipv4-address ipv4-dst)]]}\n"
                                       "\tsdtf {:type :csv-str :rules [[udpSrc (float (/ (int16 udp-src) 65535))] [udpDst (float (/ (int16 udp-dst) 65535))]]}\n"
                                       "\t(old syntax): sdtf {:type :clj-map :rules [{:offset :udp-src :transformation :int16 :name :udpSrc} {:offset :udp-dst :transformation :int16 :name :udpDst}]}\n")}
                     :sdtf :set-dsl-transformation-function}
              :prompt-string "clj-net-pcap> "}]
            (start-cli cli-opts)
            (shutdown-fn)))
      (println "Leaving (-main [& args] ...)."))))

