#! /usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#
# Convert a list of IP addresses, domain names and file hashes to a format ingestible by
# the Bro intelligence framework.

import os, sys

indicators = {'ip':'Intel::ADDR', 'dns':'Intel::DOMAIN', 'filehash':'Intel::FILE_HASH'}
report_source = 'securelist'
report_desc = 'Kaspersky Equation Group report'
report_url = 'http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/'

for indicator in indicators:
    infileslist = [filename for filename in os.listdir('.') if filename.endswith('.' + indicator + '.txt')]
    outfile = open(indicator + '.bro.intel', 'w')
    outfile.write('#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\n')
    for infilen in infileslist:
        infileh = open(infilen)
        for lioc in infileh.readlines():
            line = "{0}\t{1}\t{2}\t{3}\t{4}\n".format(
                    lioc.strip('\n'),
                    indicators[indicator],
                    report_source,
                    report_desc,
                    report_url)
            outfile.write(line)

