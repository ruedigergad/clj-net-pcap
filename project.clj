(defproject clj-net-pcap "1.8.4"
;(defproject clj-net-pcap "1.8.5-SNAPSHOT"
  :description "clj-net-pcap is a wrapper/adapter/facade (No matter how you want to call it.)
                around jNetPcap that enables and eases packet capturing and processing with Clojure."
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [org.clojure/tools.cli "1.0.214"]
                 [cli4clj "1.9.0"]
                 [clj-assorted-utils "1.19.0"]
                 [jnetpcap "1.5.r1457-1i"]]
  :min-lein-version "2.0.0"
  :aot [#"^clj-net-pcap.*"]
  :global-vars {*warn-on-reflection* true}
  :main clj-net-pcap.main
  :java-source-paths ["src-java"]
  :javac-options     ["-target" "1.8" "-source" "1.8"]
;  :jvm-opts ["-Dnio.blocksize=1048576"]
  :omit-source true
  :html5-docs-docs-dir "docs/doc"
  :html5-docs-ns-includes #"^clj-net-pcap.*"
  :html5-docs-repository-url "https://github.com/ruedigergad/clj-net-pcap/blob/master"
  :test2junit-output-dir "docs/test-results"
  :test2junit-run-ant true
  :test-selectors {:default (complement :main-cli)
                   :main-cli :main-cli}
  :plugins [[lein-cloverage "1.0.9"] [test2junit "1.4.4"] [lein-html5-docs "3.0.3"]]
  :profiles {:uberjar {:source-paths ["src" "src-main"]}
             :run {:source-paths ["src" "src-main"]}}
)
