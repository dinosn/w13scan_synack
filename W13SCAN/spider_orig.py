#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 23/08/2022
# @Author  : krasn based on w8ay's work
# @File    : spider.py

import os
import sys
from urllib.parse import urlparse

import requests
import json
import subprocess
import argparse

from lib.core.data import KB

root = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(root, "../"))
sys.path.append(os.path.join(root, "../", "W13SCAN"))
from api import modulePath, init, FakeReq, FakeResp, HTTPMETHOD, task_push_from_name, start, logger

# Crawlergo path
Excvpath = "/root/tools/crawlergo/crawlergo"

# Chrome path
Chromepath = "/home/krasn/BurpSuitePro/burpbrowser/103.0.5060.134/chrome"


def read_test():
    with open("spider_testasp.vulnweb.com.json") as f:
        datas = f.readlines()
    for data in datas:
        item = json.loads(data)
        url = item["url"]
        method = item["method"]
        headers = item["headers"]
        data = item["data"]

        try:
            if method.lower() == 'post':
                req = requests.post(url, data=data, headers=headers)
                http_model = HTTPMETHOD.POST
            else:
                req = requests.get(url, headers=headers)
                http_model = HTTPMETHOD.GET
        except Exception as e:
            logger.error("request method:{} url:{} faild,{}".format(method, url, e))
            continue

        fake_req = FakeReq(req.url, {}, http_model, data)
        fake_resp = FakeResp(req.status_code, req.content, req.headers)
        task_push_from_name('loader', fake_req, fake_resp)
    logger.info("Crawling complete, start of analysis")
    start()


def vulscan(target):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3945.0 Safari/537.36",
    }
    if target == "":
        return
    elif "://" not in target:
        target = "http://" + target
    try:
        print("trying at {}", target)
        req = requests.get(target, headers=headers, timeout=60)
        target = req.url
    except:
        pass
#        return
    netloc = urlparse(target).netloc
    logger.info("Crawling:{}".format(target))
    cmd = [Excvpath, "-c", Chromepath, "--fuzz-path", "--robots-path", "-t", "20", "--custom-headers",
           json.dumps(headers), "--max-crawled-count", "10086", "-o", "json",
           target]
    print(cmd)
    rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = rsp.communicate()
    try:
        result = json.loads(output.decode().split("--[Mission Complete]--")[1])
    except IndexError:
        return
    if result:
        all_req_list = result["req_list"]
        logger.info("Data analysis:{}".format(len(all_req_list)))
        for item in all_req_list:
            with open("spider_{}.json".format(netloc), "a+") as f:
                f.write(json.dumps(item) + '\n')
            url = item["url"]
            method = item["method"]
            headers = item["headers"]
            data = item["data"]

            try:
                if method.lower() == 'post':
                    req = requests.post(url, data=data, headers=headers)
                    http_model = HTTPMETHOD.POST
                else:
                    req = requests.get(url, headers=headers)
                    http_model = HTTPMETHOD.GET
            except Exception as e:
                logger.error("request method:{} url:{} faild,{}".format(method, url, e))
                continue

            fake_req = FakeReq(req.url, {}, http_model, data)
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push_from_name('loader', fake_req, fake_resp)
            logger.info("Scan target:{}".format(req.url))

    logger.info("Crawl complete, processing vulnerability analysis")
    start()
    logger.info("Vulnerability scan ended")
    logger.info("Issues identified:{}".format(KB.output.count()))


def init_w13scan():
    root = modulePath()
    configure = {
        "debug": False,  # debug mode 
        "level": 2,
        "timeout": 30,
        "retry": 3,
        "json": "",  # Custom output json result path,
        "html": True,
        "threads": 30,  # number of threads,
        "disable": [],
        "able": [],
        "excludes": ["google", "lastpass", '.synack.com']  # URLs that are excluded
    }
    init(root, configure)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s','--s',help="Initiate scan on domain")
    args = parser.parse_args()
    if len(sys.argv) < 2:
        print ("No arguments provided -h for help")
        exit()
    else:
        init_w13scan()
    if args.s:
        target = str(args.s.lower())
        vulscan(target)
#    read_test()
