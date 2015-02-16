#! /usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

import urllib

wantedcats = { 'CnC':0, 'Bot':0, 'Drop':0, 'DriveBySrc':0, 'Compromised':0, 'FakeAV':0, 'Blackhole':0, 'P2PCnC':0, 'EXE_Source':0, 'Mobile_CnC':0, 'Mobile_Spyware_CnC':0, 'DDoSAttacker':0 }

fcat = urllib.urlopen("categories.txt")

for l in fcat.readlines():
    (catnum, catshort, catlong) = l.split(',')
    if catshort in wantedcats:
        wantedcats[catshort] = catnum

fip = urllib.urlopen("iprepdata.txt")
for l in fip.readlines():
    (ip, category, score) = l.split(',')
    if category in wantedcats.values():
        if int(score.strip('\n')) > 100:
            print ','.join([ip, category, score.strip('\n')])

