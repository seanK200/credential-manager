from pypass import pypass, params
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
    if params.DATA_DIRNAME not in os.listdir("."):
        os.mkdir(params.DATA_DIRNAME)
    
    return False

def main():
    if need_setup():
        pypass_setup.run_setup()
    pypass.runner()

if __name__ == "__main__":
    main()