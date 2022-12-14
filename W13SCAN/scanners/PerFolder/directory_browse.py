#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 4:46 PM
# @Author  : w8ay
# @File    : directory_browse.py
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Directory listing'
    desc = '''Directory listing'''

    def audit(self):

        resp_str = self.response.text
        flag_list = [
            "directory listing for",
            "<title>directory",
            "<head><title>index of",
            '<table summary="directory listing"',
            'last modified</a>',

        ]
        for i in flag_list:
            if i in resp_str.lower():
                result = self.new_result()
                result.init_info(self.requests.url, "Directory listing", VulType.SENSITIVE)
                result.add_detail("payload detect", self.requests.raw, self.response.raw,
                                  "identified:{}".format(i), "", "", PLACE.GET)
                self.success(result)
                break
