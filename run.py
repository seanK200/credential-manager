from pypass import pypass
from pypass.params import DATA_DNAME
import pypass_setup

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

def main():
    if need_setup():
        pypass_setup.run_setup()
    pypass.main()

if __name__ == "__main__":
    main()