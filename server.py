#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2015 breakwall
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import os

if __name__ == "__main__":
    import inspect

    os.chdir(
        os.path.dirname(
            os.path.realpath(inspect.getfile(inspect.currentframe()))
        )
    )

from multiprocessing import Process

import web_transfer
from configloader import get_config
from shadowsocks import shell

class MainThread(Process):
    def __init__(self, obj):
        Process.__init__(self)
        self.obj = obj

    def run(self):
        self.obj.thread_db(self.obj)

    def stop(self):
        self.obj.thread_db_stop()


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)-s: %(message)s"
    )

    shell.check_python()

    if get_config().API_INTERFACE == "modwebapi":
        threadMain = MainThread(web_transfer.WebTransfer)
    threadMain.start()

    try:
        while threadMain.is_alive():
            threadMain.join(10.0)
    except (KeyboardInterrupt, IOError, OSError):
        import traceback

        traceback.print_exc()
        threadMain.stop()

if __name__ == "__main__":
    main()
