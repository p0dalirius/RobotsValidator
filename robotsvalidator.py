#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : robotsvalidator.py
# Author             : Podalirius (@podalirius_)
# Date created       : 30 Nov 2021


# https://www.robotstxt.org/norobots-rfc.txt

import argparse
import re
import os
import sys
import readline
import requests
import urllib.parse

readline.parse_and_bind('tab: complete')
readline.set_completer_delims('\n')


class Logger(object):
    def __init__(self, debug=False, logfile=None, nocolors=False):
        super(Logger, self).__init__()
        self.__debug = debug
        self.__nocolors = nocolors
        self.logfile = logfile
        #
        if self.logfile is not None:
            if os.path.exists(self.logfile):
                k = 1
                while os.path.exists(self.logfile + (".%d" % k)):
                    k += 1
                self.logfile = self.logfile + (".%d" % k)
            open(self.logfile, "w").close()

    def print(self, message=""):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print(nocolor_message)
        else:
            print(message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write(nocolor_message + "\n")
            f.close()

    def info(self, message):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print("[info] %s" % nocolor_message)
        else:
            print("[info] %s" % message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write(nocolor_message + "\n")
            f.close()

    def debug(self, message):
        if self.__debug == True:
            nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
            if self.__nocolors:
                print("[debug] %s" % nocolor_message)
            else:
                print("[debug] %s" % message)
            if self.logfile is not None:
                f = open(self.logfile, "a")
                f.write("[debug] %s" % nocolor_message + "\n")
                f.close()

    def error(self, message):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print("[error] %s" % nocolor_message)
        else:
            print("[error] %s" % message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write("[error] %s" % nocolor_message + "\n")
            f.close()


class RobotsTXT(object):
    def __init__(self, robotsdata, logger):
        super(RobotsTXT, self).__init__()
        self.logger = logger
        self.robotsdata = robotsdata
        self._parse()

    def _parse(self):
        # Cleanup empty lines and parse content
        self.entries = []
        for line in self.robotsdata.split('\n'):
            if len(line.strip()) != 0:
                if line.startswith("#"):
                    content = line.lstrip("#").strip()
                    self.entries.append({"type": "commentary", "content": content, "raw": line})
                elif line.lower().startswith("disallow"):
                    content = line.split(':', 1)[1].lstrip()
                    self.entries.append({"type": "disallow", "content": content, "raw": line})
                elif line.lower().startswith("allow"):
                    content = line.split(':', 1)[1].lstrip()
                    self.entries.append({"type": "allow", "content": content, "raw": line})

    def _to_re_regex(self, data):
        # replace * by .*
        data = re.sub("^\*", '.*', data)
        data = re.sub("([^.])\*", '\\1.*', data)
        return data

    def validate(self, url):
        path = None
        if '://' in url:
            matched = re.match("([a-z]+://[^/]+[/]?)(.*)", url)
            if matched is not None:
                path = '/' + matched.group(2)
        else:
            path = url
        logger.debug("Using path '%s'" % path)

        l_allow, l_disallow = [], []
        for entry in self.entries:
            if entry["type"] == "allow":
                rule_regex = self._to_re_regex(entry["content"])
                if re.match(rule_regex, path):
                    logger.debug("%-50s : \x1b[92maccepted by rule\x1b[0m" % ("Rule 'Allow: %s'" % entry["content"]))
                    l_allow.append(entry)
                else:
                    logger.debug("%-50s : \x1b[91mrejected by rule\x1b[0m" % ("Rule 'Allow: %s'" % entry["content"]))
            elif entry["type"] == "disallow":
                rule_regex = self._to_re_regex(entry["content"])
                if re.match(rule_regex, path):
                    logger.debug("%-50s : \x1b[91mrejected by rule\x1b[0m" % ("Rule 'Disallow: %s'" % entry["content"]))
                    l_disallow.append(entry)
                else:
                    logger.debug("%-50s : \x1b[92maccepted by rule\x1b[0m" % ("Rule 'Disallow: %s'" % entry["content"]))

        return l_allow, l_disallow


def parseArgs():
    parser = argparse.ArgumentParser(description="Description message")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    parser.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="No colors mode.")
    parser.add_argument("-l", "--logfile", dest="logfile", type=str, default=None, help="Log file to save output to.")

    parse_robots_source = parser.add_mutually_exclusive_group()
    parse_robots_source.add_argument("-r", "--robots-file", dest="robots_file", default=None, help='robots.txt file')
    parse_robots_source.add_argument("-R", "--robots-url", dest="robots_url", default=None,
                                     help='robots.txt location URL.')

    options = parser.parse_args()

    if options.robots_file is None and options.robots_url is None:
        print("%s: error: Either -r/--robots-file or -R/--robots-url are required." % sys.argv[0])
        exit(0)

    return options


if __name__ == '__main__':
    options = parseArgs()
    logger = Logger(debug=options.debug, nocolors=options.no_colors, logfile=options.logfile)

    robotsdata = None
    if options.robots_file is not None:
        logger.debug("Reading file '%s' ..." % options.robots_file)
        if os.path.exists(options.robots_file):
            f = open(options.robots_file, 'r')
            robotsdata = f.read()
            f.close()
            logger.debug("Read %d bytes." % (len(robotsdata)))
        else:
            logger.error("File '%s' does not exists or is not readable." % options.robots_file)
            sys.exit()
    elif options.robots_url is not None:
        logger.debug("Querying '%s' ..." % options.robots_url)
        r = requests.get(options.robots_url)
        if r.status_code == 200:
            robotsdata = r.content.decode("UTF-8")
            logger.debug("HTTP %d response: %d bytes returned." % (r.status_code, len(r.content)))
        else:
            logger.error("Access to '%s' returned a %d status code." % (options.robots_url, r.status_code))
            sys.exit()

    robotstxt = RobotsTXT(robotsdata, logger=logger)

    prompt = "[%s]> " % urllib.parse.urlparse(options.robots_url).netloc

    try:
        while True:
            url = input(prompt)
            if len(url) != 0:
                l_allow, l_disallow = robotstxt.validate(url)
                if len(l_allow) == 0 and len(l_disallow) == 0:
                    logger.print("\x1b[1;92mAllowed by robots.txt!\x1b[0m (allow:%d, disallow:%d)" % (
                    len(l_allow), len(l_disallow)))
                elif len(l_allow) != 0:
                    logger.print("\x1b[1;92mAllowed by robots.txt!\x1b[0m (allow:%d, disallow:%d)" % (
                    len(l_allow), len(l_disallow)))
                elif len(l_disallow) != 0:
                    logger.print("\x1b[1;91mNot allowed by robots.txt!\x1b[0m (allow:%d, disallow:%d)" % (
                    len(l_allow), len(l_disallow)))

                for rule in l_allow:
                    logger.print(" | Rule '%s'" % rule["raw"])
                for rule in l_disallow:
                    logger.print(" | Rule '%s'" % rule["raw"])
    except KeyboardInterrupt as e:
        print()
        pass
