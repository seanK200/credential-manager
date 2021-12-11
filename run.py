import sys
import pypass_setup
from pypass.params import DATA_DNAME

def need_setup():
    # deps installed?
    try:
        import cryptography.fernet
        import pyfiglet
        import rich
        import PyInquirer
    except ModuleNotFoundError:
        return True
    
    # Data dir present?
    import os
    if DATA_DNAME not in os.listdir("."):
        os.mkdir(DATA_DNAME)
    
    return False

def run():
    if need_setup():
        pypass_setup.run_setup()
    try:
        from pypass.pypass import main as pypass_main
        pypass_main()
    except ModuleNotFoundError:
        print("Error: Dependencies are not installed.")
        sys.exit(1)

if __name__ == "__main__":
    run()