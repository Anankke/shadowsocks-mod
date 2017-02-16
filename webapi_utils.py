#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import requests
from configloader import load_config, get_config
from collections import OrderedDict

class WebApi(object):

    def __init__(self):
        self.session_pool = requests.Session()

    def getApi(self, uri, params={}):
        try:
            uri_params = params.copy()
            uri_params['key'] = get_config().WEBAPI_TOKEN
            data = self.session_pool.get(
                '%s/mod_mu/%s' %
                (get_config().WEBAPI_URL, uri),
                params=uri_params,
                timeout=10).json()
            if data['ret'] == 0:
                logging.error("request %s error!wrong ret!"%(uri))
                return []
            return data['data']
        except Exception:
            import traceback
            trace = traceback.format_exc()
            logging.error(trace)
            raise Exception('network issue or server error!')


    def postApi(self, uri, params={}, raw_data={}):
        try:
            uri_params = params.copy()
            uri_params['key'] = get_config().WEBAPI_TOKEN
            data = self.session_pool.post(
                '%s/mod_mu/%s' %
                (get_config().WEBAPI_URL,
                 uri),
                params=uri_params,
                json=raw_data,
                timeout=10).json()
            if data['ret'] == 0:
                logging.error("request %s error!wrong ret!"%(uri))
                return []
            return data['data']
        except Exception:
            import traceback
            trace = traceback.format_exc()
            logging.error(trace)
            raise Exception('network issue or server error!')
