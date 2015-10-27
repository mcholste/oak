import pprint
import logging
import re

from time import *

# This function is lightning fast and has a 1 in 3000 chance at collisions at 
#  32-bits. Almost zero chance of collision if 64-bits were used.
def hasher(v):
    # 32-bit
    return hash(v) & 0xffffffff

pretty_printer = pprint.PrettyPrinter(indent=4)
def pp(val):
    pretty_printer.pprint(val)

class Logger:
    # Automatically setup a logger for any class that inherits this one
    def _log_init():
        log = logging.getLogger(__name__)
        log.setLevel(logging.DEBUG)
        streamhandler = logging.StreamHandler()
        streamhandler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(process)d\t%(thread)d\t%(asctime)s\t%(funcName)s" +
            "[%(filename)s:%(lineno)d]\t%(levelname)s\t%(message)s")
        streamhandler.setFormatter(formatter)
        log.addHandler(streamhandler)
        return log
    log = _log_init()

class Timer(Logger):
    def __init__(self):
        #self.log = self._log_init_name("timer")
        self.overall_start = self.start = time()
        self.activities = []
        self.stats = []
        self.outstanding = {}
    
    def status(self, message):
        now = time()
        took = now - self.start
        self.log.debug("%s took: %f, %f since start" % 
            (message, took, (now - self.overall_start)))
        self.activities.append((took, message))
        self.start = now
        return now - self.overall_start

    def stat_start(self, name):
        self.outstanding[name] = time()

    def stat_end(self, name, count):
        try:
            took = time() - self.outstanding[name]
            rate = count / took
            self.stats.append((took, rate, name))
            self.log.debug("%s took %f at rate %f" % (name, took, rate))
            del self.outstanding[name]
        except Exception as e:
            self.log.error(e)

    def print_report(self):
        for tup in self.activities:
            print "%f\t%s" % tup
        for tup in self.stats:
            print "%f\t%f\t%s" % tup

    def print_report_sorted(self):
        for tup in sorted(self.activities, key=itemgetter(0), reverse=True):
            print "%f\t%s" % tup
        for tup in sorted(self.stats, key=itemgetter(0), reverse=True):
            print "%f\t%f\t%s" % tup

class Utils:
    FIELD_TYPE_STRING = 0
    FIELD_TYPE_NUMERIC = 1
    FIELD_TYPE_IPv4 = 2

    ipv4_check = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    def flatten(self, key, doc, target):
        for k in doc.keys():
            v = doc[k]
            if type(v) is dict:
                self.flatten(key + "." + k, v, target)
            elif type(v) is list:
                self.flatten_list(key, v, target)
            else:
                target[key + "." + k] = v

    def flatten_list(self, key, given_list, target):
        items = list()
        for v in given_list:
            if type(v) is dict:
                self.flatten(key, v, target)
            elif type(v) is list:
                self.flatten_list(key + "_", v, target)
            else:
                items.append(v)
        if len(items):
            target[key] = ",".join(items)
