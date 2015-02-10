#!/usr/bin/env python

import subprocess
from ConfigParser import SafeConfigParser
import sys
import requests
import hashlib
import re


class MonitorSslyze(object):
    """Run SSLyze and compares results to a previous result stored as a hash"""

    def __init__(self):
        self._compareHashes = True
        self._debug = False

    def debug(self, flag):
        """debug level loggging set to false by default"""
        if flag:
            print '[DEBUG]: Debug Level Enabled'
            self._debug = True

    def compare(self, value):
        """compares generated & precomputed hash by default"""

        # set compare to False
        if value:
            self._compareHashes = True
        elif not value:
            self._compareHashes = False
        else:
            print '[ERROR]: compare() - Unrecognized Option'

    def setSslyze(self, sslyzePath):
        """Set SSLyze Path"""
        self._sslyzePath = sslyzePath
        print '[INFO]: Sslyze Path:', self._sslyzePath

    def config(self, configFile, configSection):
        """Configuration options for MonitorSSLyze."""
        self._configFile = configFile
        self._configSection = configSection

        print '[INFO]: Config File Name:', self._configFile

        # configure config parser
        self.parser = SafeConfigParser()
        self.parser.read(self._configFile)

    def getConfigValue(self, section, value):
        """Reads config hash file and returns value"""
        value = self.parser.get(section, value)
        return value

    def runSslyze(self, targetUrl):
        """Runs SSLyze with specific options"""
        self._sslyzeTargetUrl = targetUrl

        # sslyze commandline options
        # --nb_retries increased from default connections(4)
        #   to ensure timeout/connection errors are not observed
        SSLYZE_XML_OPTIONS = '--xml_out=results.xml'
        SSLYZE_REGULAR_SETTINGS = '--regular'
        SSLYZE_RETRIES_SETTINGS = '--nb_retries=15'

        # spawn python process to run sslyze.py
        sylyzeOutput = open('sslyze.out', 'w')
        try:
            process = subprocess.Popen(
                ['python',
                    self._sslyzePath,
                    self._sslyzeTargetUrl,
                    SSLYZE_XML_OPTIONS,
                    SSLYZE_REGULAR_SETTINGS,
                    SSLYZE_RETRIES_SETTINGS],
                stdout=sylyzeOutput,
                shell=False)
            process.wait()
            sylyzeOutput.flush()
        except requests.ConnectionError, e:
            print '[ERROR]: Unable to run sslyze'
            print e
            sys.exit(0)

    def hashSslyzeResults(self):

        # open sslyze xml ouput file and removes totalScanTime line
        # <results defaultTimeout="5" httpsTunnel="None" startTLS="None"
        #   totalScanTime="11.6196300983">

        f = open('results.xml')
        output = []
        for line in f:
            timeoutMatch = re.match(".*timeout.*", line)
            timeMatch = re.match(".*totalScanTime.*", line)
            if not timeMatch:
                output.append(line)
            if timeoutMatch:
                print '[ERROR]: Timeout connection detected'
        f.close()
        hash = self.hashFor(output)
        # if debug
        if self._debug:
            print '[DEBUG]: Results Hash'
            print hash
        return hash

    def hashFor(self, data):
        hashId = hashlib.sha256()
        for buf in data:
            hashId.update(buf.encode())
        return hashId.hexdigest()

    def verify(self, url, configOption):
        print '[INFO]: Analyzing URL: ', url

        if self._compareHashes:
            print '[INFO]: In Compare Mode'
        else:
            print '[INFO]: In Generate Hash Mode'

        # run sslyze
        self.runSslyze(url)
        # run sslyze
        self.runSslyze(url)
        # get precomputed hash
        resultsHash = self.hashSslyzeResults()

    # if in generate hash mode
        if not self._compareHashes:
            print '[INFO]: Generated Hash:', resultsHash

        # if in compare mode
        if self._compareHashes:
            confighash = self.getConfigValue(self._configSection, configOption)

            # if debug print precompute hash
            if self._debug:
                print '[DEBUG]: Precomputed Hash:'
                print confighash

            # compare hashes
            if self._compareHashes:
                if (resultsHash == confighash):
                    print '[INFO]: Result: No Changes'
                else:
                    print '[INFO]: Result: Response Hash Changed'
