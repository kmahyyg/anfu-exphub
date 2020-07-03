#!/usr/bin/env python3
# - encoding: utf-8 -*-
#
# PoC-in-GitHub Interpreter
# Copyright (C) 2020 kmahyyg
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free 
# Software Foundation, either version 3 of the License, or (at your option) 
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public 
# License for more details.
#
# You should have received a copy of the GNU Affero General Public License 
# along with this program. If not, see http://www.gnu.org/licenses/.
#
#
# This Program is used to extract PoC URL from JSON file inside PoC-In-GitHub Repo.
#

import os
import json
import requests
import pathlib
from bs4 import BeautifulSoup
import argparse
import html

configGlobal = None

def getAbsPath(relpath: str) -> str:
    p = pathlib.Path(relpath)
    res = p.resolve()
    if res.is_absolute():
        return str(res)
    else:
        raise IOError("Cannot Resolve to Absolute Path.")


def checkFolderExists(abspath: str) -> bool:
    p = pathlib.Path(abspath)
    return p.exists() and p.is_dir()


def searchPSS(cvestr: str) -> dict:
    errmsg = "Your Request Returned Nothing of Interest"
    baseurl = "https://packetstormsecurity.com/"
    resdict = {}
    r = requests.Session()
    r.get(baseurl)
    reshtml = r.get("https://packetstormsecurity.com/search/?q={}&s=files".format(cvestr))
    if errmsg in reshtml.text:
        return resdict
    else:
        soup = BeautifulSoup(reshtml.text, "lxml")
        tempres1 = soup.find_all("dt")
        for link in tempres1:
            # print(link.a)
            if link.a:
                resdict[html.unescape(link.a.text)] = baseurl + link.a["href"]
            else:
                pass
        return resdict


def searchCVEDetails(cveid: str) -> str:
    errmsg = "Unknown CVE ID"
    r = requests.Session()
    reshtml = r.get("https://www.cvedetails.com/cve/{}/".format(cveid))
    if errmsg in reshtml.text:
        raise IOError("CVE Not Found!")
    else:
        soup = BeautifulSoup(reshtml.text, "lxml")
        descr = soup.find("meta", attrs={"name":"description"})["content"]
        if descr:
            descrstr = "| " + " | ".join(html.unescape(descr).split(" : ")) + " |"
        else:
            descrstr = "Error when Split Description from CVEDetails"
        return descrstr if descr else "Extract Data Error"


def readUsrConfig():
    global configGlobal
    conf = open("config.json", 'r').read()
    confj = json.loads(conf)
    confj["PiGLocation"] = getAbsPath(confj["PiGLocation"])
    if checkFolderExists(confj["PiGLocation"]):
        pass
    else:
        raise FileNotFoundError("Data Storage Error.")
    configGlobal = confj
    if configGlobal["APIProxyEnabled"]:
        print("Proxy Enabled.")
        os.environ["HTTP_PROXY"]=configGlobal["APISocks5ProxyAddr"]["http"]
        os.environ["HTTPS_PROXY"]=configGlobal["APISocks5ProxyAddr"]["https"]
    # print("Config: \n")
    # print(configGlobal)
    # print("\n")
    return confj


def getGitRepoLang(repourl: str) -> str:
    from requests.auth import HTTPBasicAuth
    # GitHub Only
    r = requests.Session()
    res = r.get("https://api.github.com/repos/{}/languages".format(repourl), auth=HTTPBasicAuth(configGlobal["GitHubUsrName"], configGlobal["GitHubToken"]))
    if res.status_code == 200:
        return list(res.json().keys())[0]
    else:
        return ""


def searchPiGDB(cveno: list) -> list:
    reslst = []
    cvenostr = "-".join(cveno)
    p = pathlib.Path(configGlobal["PiGLocation"] + "/" + str(cveno[1])).resolve()
    if p.exists() and p.is_dir():
        p = p.joinpath("./" + cvenostr + ".json")
        if p.exists():
            resdata = json.loads(open(str(p), 'r').read())
            for i in resdata:
                reslst.append([i["full_name"], i["stargazers_count"], i["updated_at"], getGitRepoLang(i["full_name"])])
        else:
            return reslst
    else:
        pass
    return reslst


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cveno",type=str, help="CVE Number like: CVE-2018-0101, case insensitive")
    finalargs = parser.parse_args()
    print("Start Parsing User Config and Input...")
    conf = readUsrConfig()
    print("Update PiGDB each time before you run this program.\n")
    pigloca = pathlib.Path(conf["PiGLocation"])
    cveipt = finalargs.cveno.upper()
    cveno = cveipt.split("-")
    if cveno[0] != "CVE" or int(cveno[1]) < 1900 or int(cveno[2]) <= 0:
        raise IOError("CVE Number must start with CVE-")
    if pigloca.exists() and pigloca.is_dir():
        if conf["GetDetailsFromCVEDetails"]:
            print("Getting CVE Details...\n")
            print(searchCVEDetails(cveipt) + " \n")
        if conf["GetAvailablePoCFromPacketStormSec"]:
            print("Trying to search PSS: \n")
            pssres = searchPSS(cveipt)
            pssresstr = ""
            if len(pssres) > 0:
                tempkdt = list(pssres.keys())
                for i in tempkdt:
                    pssresstr += "| {} | {} | \n".format(i, pssres[i])
            else:
                pssresstr = "Nothing Found in PSS.\n"
            print(pssresstr)
        print("Search in PiGDB...\n")
        pigdbres = searchPiGDB(cveno)
        pigdbresstr = ""
        if len(pigdbres) > 0:
            for i in pigdbres:
                pigdbresstr += "| {} | {} | {} | {} | {} |\n".format(i[0], "https://github.com/" + i[0] ,i[3], i[2], str(i[1]))
        else:
            pigdbresstr = "Empty Result From PiGDB.\n"
        print(pigdbresstr)
        print("Don't forget to search ExploitDB and MSF.")
        print("------------- Done ------------")
    else:
        print("Please Clone PiGDB from {} First.".format(conf["PiGUpstream"]))
        raise FileNotFoundError("Cannot Find Poc-In-GitHub.")


if __name__ == "__main__":
    main()
