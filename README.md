Shadowsocks-mod
===========

UIM 配套的后端程序

### dbq, python2 实在是太难支持了呜呜呜，请 python2 用户使用 commit 64682f18da9688667ca03ebaef2a02f48128f70a 

### Install

Debian / Ubuntu:

	apt-get -y install python-pip libffi-dev libssl-dev
	pip install -r requirements.txt

CentOS:
    yum install epel-release
    yum update
    yum install  libffi libffi-devel openssl-devel python2-pip
    
    pip install -r requirements.txt


License
-------

Copyright 2015 clowwindy

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.