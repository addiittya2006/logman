from __future__ import with_statement
import urllib2
import os
import sys
import re

try:
    from lxml import etree
except ImportError:
    try:
        import xml.etree.cElementTree as etree
    except ImportError:
        try:
            import xml.etree.ElementTree as etree
        except ImportError:
            print('Cannot find the ElementTree in your python packages')

names = {
    'xss': 'Cross-Site Scripting',
    'sqli': 'SQL Injection',
    'csrf': 'Cross-Site Request Forgery',
    'dos': 'Denial Of Service',
    'dt': 'Directory Traversal',
    'spam': 'Spam',
    'id': 'Information Disclosure',
    'rfe': 'Remote File Execution',
    'lfi': 'Local File Inclusion'
}

table = {}


class object_dict(dict):
    def __init__(self, initd=None):
        if initd is None:
            initd = {}
        dict.__init__(self, initd)

    def __getattr__(self, item):
        d = self.__getitem__(item)
        # if value is the only key in object, you can omit it
        if isinstance(d, dict) and 'value' in d and len(d) == 1:
            return d['value']
        else:
            return d

    def __setattr__(self, item, value):
        self.__setitem__(item, value)


def __parse_node(node):
    tmp = object_dict()
    # save attrs and text, hope there will not be a child with same name
    if node.text:
        tmp['value'] = node.text
    for (k, v) in node.attrib.items():
        tmp[k] = v
    for ch in node.getchildren():
        cht = ch.tag
        chp = __parse_node(ch)
        if cht not in tmp:  # the first time, so store it in dict
            tmp[cht] = chp
            continue
        old = tmp[cht]
        if not isinstance(old, list):
            tmp.pop(cht)
            tmp[cht] = [old]  # multi times, so change old dict to a list
        tmp[cht].append(chp)  # add the new one
    return tmp


def parse(xml_file):
    try:
        xml_handler = open(xml_file, 'r')
        doc = etree.parse(xml_handler).getroot()
        xml_handler.close()
        return object_dict({doc.tag: __parse_node(doc)})
    except IOError:
        print "error: problem with the filter's file"
        return {}


def get_value(array, default):
    if 'value' in array:
        return array['value']
    return default


def analyzer(data):
    exp_line, regs, array, preferences, org_line = data[0], data[1], data[2], data[3], data[4]
    done = []
    for _hash in regs[attack_type]:
        if _hash not in done:
            done.append(_hash)
            attack = table[_hash]
            cur_line = exp_line
            cur_line = urllib2.unquote(cur_line)
            if attack[0].search(cur_line):
                if attack[1] not in array[attack_type]:
                    array[attack_type][attack[1]] = []
                    array[attack_type][attack[1]].append((exp_line, attack[3], attack[2], org_line))
    return


def scalper(access,filters):
    global table
    if not os.path.isfile(access,filters):
        print "error: the log file doesn't exist"
        return
    if not os.path.isfile(filters):
        print "error: the filters file (XML) doesn't exist"
        return
    # load the XML file
    xml_filters = parse(filters)
    len_filters = len(xml_filters)
    if len_filters < 1:
        return
    # prepare to load the compiled regular expression
    regs = {}  # type => (reg.compiled, impact, description, rule)

    print "Loading XML file '%s'..." % filters
    for group in xml_filters:
        for f in xml_filters[group]:
            if f == 'filter':
                if type(xml_filters[group][f]) == type([]):
                    for elmt in xml_filters[group][f]:
                        rule, impact, description = "", -1, ""
                        if 'impact' in elmt:
                            impact = get_value(elmt['impact'], -1)
                        if 'rule' in elmt:
                            rule = get_value(elmt['rule'], "")
                            try:
                                compiled = re.compile(rule)
                            except Exception:
                                print "The rule '%s' cannot be compiled properly" % rule
                                return
                            _hash = hash(rule)
                            if impact > -1:
                                table[_hash] = (compiled, impact,rule,_hash)
                                regs[t].append(_hash)
    print "Processing the file '%s'..." % access
    sample, sampled_lines = False, []
    diff = []
    with open(access) as log_file:
        for line in log_file:
            lines += 1
            if sample and lines not in sampled_lines:
                continue
            if len(line) > 1:
                url = line
                if len(url) > 1:
                    analyzer([(url), regs,line])
    n = 0
    print "Scalp results:"
    print "\tFound %d attack patterns in %f s" % (n, tt)

def main(argc, argv):
    filters = "filter.xml"
    access = "logs2"
    scalper(access,filters)

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
