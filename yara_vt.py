#!/usr/bin/env python
##
# Yara VirusTotal Commenter
# author: adam m. swanda (https://www.deadbits.org)
#
# Scan a directory of files against a Yara rule set and
# optionally upload the Yara rule results to the VirusTotal reports
# if they exist in VT.
# Think of it as a way to give back to the community...
# You know you're already Yara scanning files, why not share your findings? :D
#
##
import os
import sys
import yara
import hashlib
import argparse
import requests


urls = {
    'comment': 'https://www.virustotal.com/vtapi/v2/comments/put',
    'scan': 'https://www.virustotal.com/vtapi/v2/file/scan',
    'report': 'https://www.virustotal.com/vtapi/v2/file/report',
}

no_report = 'The requested resource is not among the finished, queued or pending scans'
report_exists = 'Scan finished, information embedded'

# default VT comment prefix
# change this if you want, just know the rule(s) will be added to the end as a comma separated list
# e.g., "Yara rule hits: RuleName1, RuleName2"
vt_comment = 'Yara rule hits: '


def check_report(file_hash):
    """ Check if VT report exists for given file hash

    @param file_hash: MD5 hash of file
    @type str

    @return: True if found, False if not
    @rtype bool
    """
    params = {
        'apikey': api_key,
        'resource': file_hash
    }

    try:
        req = requests.post(urls['report'], params=params)
        data = req.json()
        if 'verbose_msg' in data.keys():
            if data['verbose_msg'] == no_report:
                return False
            elif data['verbose_msg'] == report_exists:
                return True
        else:
            return False
    except Exception as err:
        print '[error] failed to get report (%s - %s)' % (file_hash, str(err))
        return None


def add_comment(file_hash, comment):
    """ Submit a comment to VT for a given file hash

    @param file_hash: MD5 hash of file
    @type str

    @param comment: Comment string that gets submitted
    @type str
    """
    params = {
        'apikey': api_key,
        'resource': file_hash,
        'comment': comment
    }

    try:
        req = requests.post(urls['comment'], params=params)
        data = req.json()
        if data['response_code'] == 1:
            print '[*] comment submitted (%s - %s)' % (file_hash, comment)
        else:
            print '[error] failed to add comment'

    except Exception as err:
        print '[error] failed to add comment (%s - %s)' % (file_hash, str(err))


def load_directory(sample_dir):
    """ Return absolute paths of files in a directory with a size greater than zero

    @param sample_dir: Directory path to look in
    @type str

    @return files: list of absolute paths to files found
    @rtype list
    """
    files = []

    contents = os.listdir(sample_dir)
    for path in contents:
        p = os.path.join(sample_dir, path)
        if os.path.isfile(p) and os.path.getsize(p) > 0:
            files.append(p)

    return files


def hash_file(file_path):
    """ Get md5 hash of file object

    @param file_path: Path of file to obtain MD5 hash of
    @type str

    @return: md5 hexdigest
    @rtype str
    """
    fin = open(file_path, 'rb')
    m = hashlib.md5()
    while True:
        data = fin.read(16384)
        if not data:
            break
        m.update(data)
    return m.hexdigest()


class Yara(object):
    def __init__(self, rules_dir):
        """ Setup Yara scanner

        @param rules_dir: path to directory containing Yara rules
        @type str
        """
        self.name = '(yara)'
        self.rules_dir = rules_dir


    def scan(self, file_name):
        """ Scan a single file with Yara

        @param file_name: file path to scan
        @type str

        @return hits: list of matching Yara rule names
        @rtype list
        """
        hits = []

        rules = os.listdir(self.rules_dir)
        if len(rules) == 0:
            return None

        for _rule in rules:
            path = self.rules_dir + '/' + _rule
            r = yara.compile(path)

            matches = r.match(data=open(file_name, 'rb').read())
            for m in matches:
                if m.rule not in hits:
                    hits.append(m.rule)

        return hits


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan directory with Yara and submit matches to VirusTotal samples as comments')

    yara_group = parser.add_argument_group('Yara')
    vt_group = parser.add_argument_group('VirusTotal')

    yara_group.add_argument('-r', '--rules',
        help='yara rules directory',
        action='store',
        required=True)

    yara_group.add_argument('-s', '---samples',
        help='samples directory to scan',
        action='store',
        required=True)

    vt_group.add_argument('-k', '--key',
        action='store',
        help='virustotal API key',
        required=False)

    vt_group.add_argument('-c', '--comment',
        help='submit virustotal comments',
        action='store_true',
        default=False,
        required=True)

    args = parser.parse_args()

    global api_key
    api_key = args.key
    comment = args.comment
    rules_dir = args.rules
    sample_dir = args.samples

    if comment and not api_key:
        print 'error: you must specify an api key to submit comments'
        sys.exit(1)

    if not os.path.exists(rules_dir):
        print 'error: rules directory not found (%s)' % rules_dir
        sys.exit(1)

    scanner = Yara(rules_dir)

    if not os.path.exists(sample_dir):
        print 'error: sample directory not found (%s)' % sample_dir
        sys.exit(1)

    samples = load_directory(sample_dir)

    if len(samples) == 0:
        print 'error: no samples found in directory to scan'
        sys.exit(1)


    results = []
    for sample in samples:
        hits = scanner.scan(sample)
        if len(hits) != 0:
            print '[*] found match: %s (%s)' % (sample, hits)
            results.append({'yara': hits, 'hash': hash_file(sample)})

    if comment:
        for res in results:
            if check_report[res['hash']]:
                cmt = 'This file matched my Yara signatures: %s' % ', '.join(res['yara'])
                add_comment(res['hash'], cmt)
