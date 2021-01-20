# JumpServer v2.6.1 Unauthenticated RCE Exploit

## Dependencies

- websockets
- requests

Can be installed using: `pip3 install -r requirements.txt`

## Limitation

- Previous Connection on the server side might be reused (which was I couldn't control)
- Program might need to wait for a few seconds (same as the TCP Socket, you always don't know what's next)
- Interactive TTY is not implemented because possible WS wrapper is relatively high workload.

## Usage

- Switch to your favorite virtual Python environment
- Install dependencies: `pip3 install -r requirements.txt`
- Open `exp.py`, after the `DON'T CHANGE` block, you might need to change the `User MODIFICATION PART` like the path of jumpserver installation dir or miscellaneous part counter threshold or something else you want.
- Run `python3 ./exp.py http(s)://IP:PORT`
- The program will interactively guide you thorough the whole process.

**Note: Since the assets and system users might be modified and log files is rotating, you might need to change COUNT_THRESHOLD and select a proper asset to hack.**

## Demo

<p align="center">
  <img width="800" src="https://cdn.jsdelivr.net/gh/kmahyyg/anfu-exphub@master/jumpserver-v2.6.1-unauth-rce/jmsexp.svg">
</p>

## Reference

Reference: 
- https://mp.weixin.qq.com/s/KGRU47o7JtbgOC9xwLJARw
- https://blog.riskivy.com/jumpserver-%e4%bb%8e%e4%bf%a1%e6%81%af%e6%b3%84%e9%9c%b2%e5%88%b0%e8%bf%9c%e7%a8%8b%e4%bb%a3%e7%a0%81%e6%89%a7%e8%a1%8c%e6%bc%8f%e6%b4%9e%e5%88%86%e6%9e%90/
- https://github.com/chaitin/xray/pull/1026/files

Official related commits:
- https://github.com/jumpserver/jumpserver/commit/f04e2fa0905a7cd439d7f6118bc810894eed3f3e


## LICENSE

```
 jumpserver-v2.6.1-unauth-rce
 Copyright (C) 2020  kmahyyg @ PatMeow Ltd.
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.
 
 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
```
