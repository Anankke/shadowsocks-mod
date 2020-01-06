#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import requests
from configloader import get_config


class WebApi(object):
    def __init__(self):
        self.session_pool = requests.Session()

    def getApi(self, uri, params={}):
        r""" Send a ``GET`` request to API server. Return response["data"] or []

        :param uri: URI to request
        :param params: Optional arguments ``request`` takes
        :rtype: list
        """
        params["key"] = get_config().WEBAPI_TOKEN
        response = self.session_pool.get(
            "%s/mod_mu/%s" % (get_config().WEBAPI_URL, uri),
            params=params,
            timeout=10,
        )
        if response.status_code != 200:
            logging.error("Server error with status code: %i" %
                          response.status_code)
            raise Exception('Server Error!')

        try:
            json_data = response.json()
        except:
            logging.error("Wrong data: %s" % response.text)
            raise Exception('Server Error!')

        if len(json_data) != 2:
            logging.error("Wrong data: %s" % response.text)
            raise Exception('Server Error!')
        if json_data["ret"] == 0:
            logging.error("Wrong data: %s" % json_data["data"])
            raise Exception('Server Error!')

        return json_data["data"]

    def postApi(self, uri, params={}, json={}):
        r""" Send a ``POST`` request to API server. Return response["data"] or []

        :param uri: URI to request
        :param params: Optional arguments ``request`` takes
        :param json: Optional arguments ``json`` that ``request`` takes
        :rtype: list
        """
        params["key"] = get_config().WEBAPI_TOKEN
        response = self.session_pool.post(
            "%s/mod_mu/%s" % (get_config().WEBAPI_URL, uri),
            params=params,
            json=json,
            timeout=10,
        )
        if response.status_code != 200:
            logging.error("Server error with status code: %i" %
                          response.status_code)
            raise Exception('Server Error!')

        try:
            json_data = response.json()
        except:
            logging.error("Wrong data: %s" % response.text)
            raise Exception('Server Error!')

        if len(json_data) != 2:
            logging.error("Wrong data: %s" % response.text)
            raise Exception('Server Error!')
        if json_data["ret"] == 0:
            logging.error("Wrong data: %s" % json_data["data"])
            raise Exception('Server Error!')

        return json_data["data"]
