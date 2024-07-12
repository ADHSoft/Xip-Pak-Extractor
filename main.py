import keyGrabber, os, sys, pathlib, env
from extractor import extract

def extractMany(dir_:str = "./", **kwargs):
    files = os.listdir( dir_ )
    if "inputFiles" in files:
        files += os.listdir( dir_ + "inputFiles/")
    extracted = 0
    for file_ in (f for f in files if len(f) > 4 and f[-4:] == ".pak") :
        print(f"Extracting {file_.split('/')[-1]}")
        try:
            extract(dir_+file_ , **kwargs)
        except Exception as e:
            print(e)
        extracted += 1
    if extracted == 0:
        print("No .pak files found.")
            

def autoExtractAll():
    keyGrabber.main()
    extractMany(  )

if __name__ == "__main__":
    kwargs_ = {}
    if len(sys.argv) > 1:
        if "-nofolders" in sys.argv:
            kwargs_["noIndividualFoldersParam"] = True
        if "-getkeys" in sys.argv:
            keyGrabber.main( )
        if "-extractall" in sys.argv:
            extractMany( **kwargs_ )
        if ".pak" in "".join(sys.argv):
            for file_ in [a for a in sys.argv if len(a) >= 4 and a[-4:] == ".pak"]:
                print(f"Extracting {pathlib.Path(file_).name}")
                try:
                    extract( file_ , **kwargs_)
                except Exception as e:
                    print(e)
        else:
            extractMany( **kwargs_ )
    else:
        if ( env.RELEASE_BUILD ) :
            print(f'''No file specified.
Usages:
    Easy mode: Automatically extract all paks in the folder (place a game .exe in the root folder also) : {env.COMMAND_NAME}

    Extract a file: {env.COMMAND_NAME} file1.pak
    Extract all paks in the folder : {env.COMMAND_NAME} -extractall
                  
    parameter "-nofolders" : do not make individual pak folders.
              
Requirement: The keys, or an .exe file with them , must be placed in this folder.
Some known files containing the keys are: TR1.exe , O2Mania*.exe , djmax*.exe , Pak Extract.exe , yomax.exe
For trilogy (not implemented yet), you must also be able to get USB_16128_10.dat or get it with a tool that reads the usb stick .
                  
Executing easy mode...
''')
            autoExtractAll()
        else:
            ...






'''def main_profile(fileName : str = "./System.pak"):
    import cProfile

    logging.basicConfig(level=logging.ERROR)
    cProfile.run(f"openXip('{fileName}')", "profile_output.prof", sort="cumulative" )
    stats = pstats.Stats("profile_output.prof")
    stats.sort_stats('cumulative')
    stats.print_stats(30)'''