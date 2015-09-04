from __future__ import with_statement
import time, base64, urllib2
import os, sys, re


def analyzer(url):
    for reg in regs:
        method, cur_line = url.split(" ")
        cur_line = urllib2.unquote(cur_line)
        if reg.search(cur_line):
            print("Possible attack on %s" + cur_line)
    return


def scalper(access, filters):
    global table
    if not os.path.isfile(access, filters):
        print "error: Log file can't be accessed !"
        return
    with open(access) as log_file:
        for line in log_file:
            if len(line) > 1:
                url = line
                if len(url) > 1:
                    analyzer(url)
    print "Scalp results:"


def main(argc, argv):
    access = "logs2"
    scalper(access)


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
