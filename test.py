import shutil,os
from config import Root_Path
from subDomainsBrute import subDomainsBruteMain
from Subfinder.subfinderMain import subfinderScan
# def delModel():
#     saveFolderList=['saveCplus','saveJS','saveSub','saveXray']
#     for tempFolder in saveFolderList:
#         shutil.rmtree("{}\\save\\{}".format(Root_Path,tempFolder))
#         os.mkdir("{}\\save\\{}".format(Root_Path,tempFolder))
#     return

def test(target,filename):
    try:
        subfinderScan(target,filename)
    except Exception as e:
        print(e)
        pass


def main():
    test('baidu.com','aaa.txt')
    return

if __name__ == '__main__':
    main()