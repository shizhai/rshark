from datetime import datetime

import sys

os_platform = sys.platform.lower()

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = { "gray"  : "\033[0;37m",
               "green" : "\033[0;32m",
               "orange": "\033[0;33m",
               "red"   : "\033[0;31m" }
ENDCOLOR = "\033[1;0m"

if os_platform.startswith("win"):
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORCODES["gray"] = Fore.LIGHTBLACK_EX
    COLORCODES["green"] = Fore.GREEN
    COLORCODES["orange"] = Fore.LIGHTYELLOW_EX
    COLORCODES["red"] = Fore.RED
    ENDCOLOR=""

global_log_level = INFO
def log(level, msg, color=None, showtime=True):
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