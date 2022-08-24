#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/11 4:27 PM
# @Author  : w8ay
# @File    : phpinfo_craw.py

import requests

from lib.core.common import generateResponse
from lib.core.data import conf
from lib.core.enums import WEB_PLATFORM, VulType, PLACE
from lib.core.plugins import PluginBase
from lib.helper.helper_phpinfo import get_phpinfo


class W13SCAN(PluginBase):
    desc = '''Check if the phpinfo file exists in this directory'''
    name = 'phpinfo'

    def audit(self):
        if WEB_PLATFORM.PHP in self.response.programing or conf.level >= 2:
            headers = self.requests.headers
            variants = [
                "phpinfo.php",
                "pi.php",
                "php.php",
                "i.php",
                "test.php",
                "temp.php",
                "info.php",
            ]
            for phpinfo in variants:
                testURL = self.requests.url.rstrip("/") + "/" + phpinfo
                r = requests.get(testURL, headers=headers)
                flag = "<title>phpinfo()</title>"
                if flag in r.text:
                    info = get_phpinfo(r.text)
                    result = self.new_result()
                    result.init_info(self.requests.url, "phpinfo identified", VulType.SENSITIVE)
                    result.add_detail("payload detect", r.reqinfo, generateResponse(r),
                                      '\n'.join(info), "", "", PLACE.GET)
                    self.success(result)
