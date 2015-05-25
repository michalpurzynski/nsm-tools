#! /usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

import os, sys
import json
import urllib.request
import csv
import io
from dateutil.parser import parse
import datetime
import ipaddress

wantedcats = { 'CnC':100, 'Drop':100, 'DriveBySrc':100, 'Compromised':100, 'FakeAV':100, 'Blackhole':100, 'P2PCnC':100, 'Mobile_CnC':100, 'Abused TLD':100, 'SelfSignedSSL':100 }

headers = { 'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20150507 Firefox/37.0',
            'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' : 'en-US,en;q=0.5',
            'Accept-Encoding' : 'identify',
            'Connection' : 'keep-alive' }

top_path = '/var/www'

def fetch_list(url):

    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request) as data:
        return io.StringIO(data.read().decode('utf-8'))

def filter_list_csv(ioc_list):

    url = 'https://rules.emergingthreatspro.com/<code>/reputation/categories.txt'
    filename = top_path + '/' + 'iqrisk.ioc.cat.suricata'

    filtered_ioc_list = {}
    categories_to_num = {}
    categories_to_names = {}

    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request) as data:
        with open(filename, 'w') as f:
            for line in data.readlines():
                f.write(line.decode('ascii','ignore'))
                (catnum, catname, catdesc) = line.decode('ascii','ignore').split(',')
                categories_to_num[catname] = catnum
                categories_to_names[str(catnum)] = catname

    now = datetime.datetime.now()
    iocreader = csv.DictReader(ioc_list, delimiter=',', dialect='unix')
    for line in iocreader:
        # {' category': '29', ' ports (|)': '443 4444 5022', 'ip': '1.1.1.3', ' score': '120', ' first_seen': '2012-05-16', ' last_seen': '2015-01-20'}
        # yes, spaces, spaces everywhere!!
        category = line[' category']
        if category in categories_to_names:
            category_name = categories_to_names[category]
        else:
            category_name = category
        score = line[' score']
        lastseen = line[' last_seen']
        if 'ip' in line:
            ioc_type = 'ip'
        elif 'domain':
            ioc_type = 'domain'
        indicator = line[ioc_type]
        if category_name in wantedcats:
            if int(score) > int(wantedcats[category_name]):
                days_from_last_seen = now - parse(lastseen)
                if not days_from_last_seen.days > 5:
                    if not indicator in filtered_ioc_list:
                        filtered_ioc_list[indicator] = {}
                    filtered_ioc_list[indicator][category] = { 'desc': category_name + '_' + score, 'score': score, 'lastseen': lastseen }

    f.close()

    return filtered_ioc_list

def write_bro_intel(data, listtype):

    if listtype == 'addr':
        filename = 'iqrisk.ioc.addr.bro'
        ioctype = 'Intel::ADDR'
    elif listtype == 'domain':
        filename = 'iqrisk.ioc.domain.bro'
        ioctype = 'Intel::DOMAIN'

    with open(top_path + '/' + filename, 'w') as f:
        print('#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url', file=f)
        for indicator, outdict in data.items():
            for catnum, indict in outdict.items():
                print('\t'.join([indicator, ioctype, indict['desc'], 'IQRisk', 'http://www.emergingthreats.com']), file=f)

    f.close()

def write_suricata_intel(data):

    filename = 'iqrisk.ioc.addr.suricata'

    with open(top_path + '/' + filename, 'w') as f:
        for indicator, outdict in data.items():
            for catnum, indict in outdict.items():
                print(','.join([indicator, catnum, indict['score']]), file=f)

    f.close()

def main():

    urls = { 'domain': 'https://rules.emergingthreatspro.com/<code>/reputation/detailed-domainrepdata.txt',
            'addr': 'https://rules.emergingthreatspro.com/<code>/reputation/detailed-iprepdata.txt' }

    for listtype, url in urls.items():
        data = fetch_list(url)
        filtered_ioc_list = filter_list_csv(data)
        write_bro_intel(filtered_ioc_list, listtype)

    write_suricata_intel(filtered_ioc_list)

if __name__ == "__main__":
    main()

