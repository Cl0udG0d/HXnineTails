import shutil,os
from config import Root_Path

def delModel():
    saveFolderList=['saveCplus','saveJS','saveSub','saveXray']
    for tempFolder in saveFolderList:
        shutil.rmtree("{}\\save\\{}".format(Root_Path,tempFolder))
        os.mkdir("{}\\save\\{}".format(Root_Path,tempFolder))
    return

def test():
    return

def main():
    delModel()
    return

if __name__ == '__main__':
    main()