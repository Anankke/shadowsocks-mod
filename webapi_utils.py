#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import requests
from configloader import load_config, get_config
from collections import OrderedDict


def getApi(uri, params={}):
    try:
        uri_params = params.copy()
        uri_params['key'] = get_config().WEBAPI_TOKEN
        data = requests.get(
            '%s/mod_mu/%s' %
            (get_config().WEBAPI_URL, uri), params=uri_params).json()
        if data['ret'] == 0:
            return None
        return data['data']
    except Exception:
        return None


def postApi(uri, params={}, raw_data={}):
    try:
        uri_params = params.copy()
        uri_params['key'] = get_config().WEBAPI_TOKEN
        data = requests.post(
            '%s/mod_mu/%s' %
            (get_config().WEBAPI_URL,
             uri),
            params=uri_params,
            json=raw_data).json()
        if data['ret'] == 0:
            return None
        return data['data']
    except Exception:
        return None
