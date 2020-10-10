#!/usr/bin/python
# -*- coding: utf-8 -*-
# example:
#  cfg4 = Config("smb4.ini")

import sys, os
from pprint import pprint
import configparser

class Config():

    config_path = None
    config = None

    def __init__(self, config_path=None, debug=False):
      self.debug=debug
      self.config_path=config_path
      if self.config_path:
        self.config=self.read_config(self.get_config_path())

    def get_config_path(self):
        if "--config-path" in sys.argv and len(sys.argv) >= 3:
            self.config_path = sys.argv[2]
        if "--help" in sys.argv or "-h" in sys.argv:
            self.display_help_text()
            exit(0)
        if not os.path.isfile(self.config_path):
            self.shutdown_with_error(
                "Configuration file not found. Expected it at '" + self.config_path + "'.")
        return self.config_path

    def dump(self):
      for sec in self.config.sections():
        pprint(sec)
        for par in self.config[sec]:
          pprint('%s = %s' % (par,self.config[sec][par]))

    def read_config(self, file_name):
        try:
            config = configparser.ConfigParser()
            config.read(file_name, encoding="UTF-8")
        except KeyError as e:
            self.shutdown_with_error(
                "Configuration file is invalid! (Key not found: " + str(e) + ")")
        if self.debug:
          self.dump()
        return config

    def shutdown_with_error(self, message):
        message = "Error! " + str(message)
        message += "\nCurrent configuration file path: '" + \
            str(self.config_path) + "'."
        if config is not None:
            message += "\nCurrent configuration: " + str(config)
        print(message)
        exit(-1)

    def log_warning(self, message):
        print("Warning! " + message)

    def display_help_text(self):
        print("Options:")
        print("\t--help: Display this help information")
        print("\t--config-path <path/to/config/file>: "
              "Override path to config file (defaults to same directory as the script is)")
        exit(0)

if __name__ == '__main__':
  cfg4 = Config("smb4.ini")
  cfg4.dump()
