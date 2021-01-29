import re
import shutil

import requests
from subDomainsBrute import subDomainsBruteMain
from Sublist3r import Sublist3rMain
from Subfinder import subfinderMain
from OneForAll import oneforallMain
from CScan import CScan
from JSmessage.jsfinder import JSFinder
import config
from ServerJiang.jiangMain import SendNotice
import os
import hashlib




def main():
    subDomainsBruteMain.subDomainsBruteScan('wkj.work',"aa")
    return

if __name__ == '__main__':
    main()