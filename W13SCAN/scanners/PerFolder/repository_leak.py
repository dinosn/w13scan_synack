#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 3:18 PM
# @Author  : w8ay
# @File    : sourceleak.py
import re

import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''Dynamically find source code leaks repositories'''
    name = '.git .svn .bzr .hg'

    def audit(self):

        flag = {
            "/.svn/all-wcprops": "svn:wc:ra_dav:version-url",
            "/.git/config": 'repositoryformatversion[\s\S]*',
            "/.bzr/README": 'This\sis\sa\sBazaar[\s\S]',
            '/CVS/Root': ':pserver:[\s\S]*?:[\s\S]*',
            '/.hg/requires': '^revlogv1.*'
        }
        headers = self.requests.headers
        for f in flag.keys():
            _ = self.requests.url.rstrip('/') + f
            r = requests.get(_, headers=headers)
            if re.search(flag[f], r.text, re.I | re.S | re.M):
                result = self.new_result()
                result.init_info(self.requests.url, "repository leak", VulType.SENSITIVE)
                result.add_detail("payload detect", r.reqinfo, generateResponse(r),
                                  "identified:{}".format(flag[f]), "", "", PLACE.GET)
                self.success(result)
