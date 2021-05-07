#!/usr/bin/python
# -*- coding: UTF-8 -*-
import importloader

g_config = None


DEFAULT_CONFIG = {
    "GET_PORT_OFFSET_BY_NODE_NAME" : False
}


def set_default_config(cfg):
    for key in DEFAULT_CONFIG:
        if not hasattr(cfg, key):
            setattr(cfg, key, DEFAULT_CONFIG[key])


def load_config():
    global g_config
    g_config = importloader.loads(["userapiconfig", "apiconfig"])
    set_default_config(g_config)


def get_config():
    return g_config


load_config()
