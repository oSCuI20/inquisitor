# -*- coding: utf-8 -*-
#
# ./osi-model/data-link/__layer__.py
# Eduardo Banderas Alba
# 2022-08
#
# Aux functions
#
import sys, json

from importlib        import import_module
from importlib.util   import find_spec

def logger(msg, out=sys.stdout):
  if not msg:
    return

  try:
    if isinstance(msg, dict) or isinstance(msg, list) or isinstance(msg, tuple):
      msg = json.dumps(msg, indent=2)
  except:
    pass

  out.write(msg + "\n")
#logger

def tohex(b):
  return f'{b:02x}'
#tohex


def halt(msg, code = 0):
  try:
    msg = json.dumps(json.loads(msg), indent=2)
  except:
    pass

  sys.stdout.write(msg.strip() + '\n')
  sys.exit(code)
#_halt


def halt_with_doc(msg, doc, program, code = 0):
  halt('\n' + msg + '\n' + '-' * 80 + doc.format(program), code)
#halt_with_doc


def load_module(path, module_name):
  return getattr(import_module(path), module)
