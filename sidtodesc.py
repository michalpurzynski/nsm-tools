#! /usr/bin/env python

import re

f = open("downloaded.rules", "r")
f2 = open("disablesid.conf", "r")
r = re.compile('^#|^alert')
r2 = re.compile('^\ sid:')
r3 = re.compile('^1:[0-9]+$')

desc2sid = dict()

for l in f.readlines():
    if r.search(l):
        sigtable = l.split(';')
        for i in sigtable:
            if r2.search(i):
                sidnum = i.split(':')
                desc2sid[sidnum[1]] = sigtable[0]

for l in f2.readlines():
    if r3.search(l):
        dissidentry = l.split(':')
        dissidnum = dissidentry[1].strip('\n')
        if not dissidnum in desc2sid:
            print '#' + dissidnum + ' could not be resolved, skipping'
        else:
            print desc2sid[dissidnum]
            print '1:' + dissidnum

