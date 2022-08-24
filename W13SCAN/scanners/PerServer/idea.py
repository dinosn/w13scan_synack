#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/5/10 8:53 PM
# @Author  : w8ay
# @File    : idea.py

from urllib.parse import urlparse

import requests
from lxml import etree

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'idea workspace'

    def audit(self):
        headers = self.requests.headers
        p = urlparse(self.requests.url)
        domain = "{}://{}/".format(p.scheme, p.netloc)
        payload = domain + ".idea/workspace.xml"
        r = requests.get(payload, headers=headers, allow_redirects=False)
        path_lst = []
        if '<component name="' in r.text:
            root = etree.XML(r.text.encode())
            for e in root.iter():
                if e.text and e.text.strip().find('$PROJECT_DIR$') >= 0:
                    path = e.text.strip()
                    path = path[path.find('$PROJECT_DIR$') + 13:]
                    if path not in path_lst:
                        path_lst.append(path)
                for key in e.attrib:
                    if e.attrib[key].find('$PROJECT_DIR$') >= 0:
                        path = e.attrib[key]
                        path = path[path.find('$PROJECT_DIR$') + 13:]
                        if path and path not in path_lst:
                            path_lst.append(path)
            if path_lst:
                result = self.new_result()
                result.init_info(self.requests.url, "idea workspace", VulType.DIRSCAN)
                result.add_detail("payload detect", r.reqinfo, generateResponse(r),
                                  "List of sensitive directories:{}".format(repr(path_lst)), "", "", PLACE.GET)
                self.success(result)
