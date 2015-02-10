#!/bin/bash

# SSLyze Mode - Compare Hash
python healthcare_ssl_monitor.py --config-file sslyze.monitor.config --sslyze-path /path/to/sslyze/sslyze.py

# SSLyze Mode - Generate Hash
python healthcare_ssl_monitor.py --generate-hash --sslyze-path /path/to/sslyze/sslyze.py
