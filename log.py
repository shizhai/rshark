from datetime import datetime
from colorama import init, Fore, Back, Style

import sys

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = { "gray"  : "\033[0;37m",
               "green" : "\033[0;32m",
               "orange": "\033[0;33m",
               "red"   : "\033[0;31m" }
ENDCOLOR = "\033[1;0m"

global_log_level = INFO

global_log_init = False

def log(level, msg, color=None, showtime=True):
    if sys.platform.lower().startswith("win"):
        global global_log_init
        global COLORCODES
        global ENDCOLOR
        if not global_log_init:
            init(autoreset=True)
            global_log_init = True

        COLORCODES["gray"] = Fore.LIGHTBLACK_EX
        COLORCODES["green"] = Fore.GREEN
        COLORCODES["orange"] = Fore.LIGHTYELLOW_EX
        COLORCODES["red"] = Fore.RED
        ENDCOLOR=""

    if level < global_log_level: return
    if level == DEBUG   and color is None: color="gray"
    if level == INFO and color is None: color="green"
    if level == WARNING and color is None: color="orange"
    if level == ERROR   and color is None: color="red"
    msg = (datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + ENDCOLOR

    print(msg)

def change_log_level(delta):
	global global_log_level
	global_log_level += delta