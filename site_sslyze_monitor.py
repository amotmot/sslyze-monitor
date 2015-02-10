#!/usr/bin/env python

import sslyze_monitor
import logging
from optparse import OptionParser

if __name__ == "__main__":

    # set logger
    LOG_FILENAME = 'sslyze.monitor.out'
    logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG)

    # Monitor URLs
    PROD_URL = "www.site.com:443"

    # Command-line arguments
    parser = OptionParser()
    parser.add_option("-c", "--config-file", dest="configfile", metavar="FILE")
    parser.add_option("-s", "--sslyze-path", dest="sslyze", metavar="FILE")
    parser.add_option(
        "-g",
        "--generate-hash",
        dest="generate",
        default=False,
        action="store_true")
    (options, args) = parser.parse_args()

    # Config
    monitor = sslyze_monitor.MonitorSslyze()
    monitor.debug(1)
    monitor.setSslyze(options.sslyze)

    # Generate Hash
    if options.generate:
        monitor.compare(False)
    # Compare generated and precomputer hash
    if not options.generate:
        monitor.compare(True)
        monitor.config(options.configfile, 'Hashes')

    # Run SSLyze-Monitor against target
    logging.info('Running SSLyze Monitor')

    logging.info('Test - Site')
    monitor.verify(PROD_URL, 'site.prod')

    f = open('sslyze.monitor.out.txt', 'r')
    sslyzeOutput = f.read().splitlines()
    sslyzeOutputList = '\n'.join(sslyzeOutput)
    f.close()
