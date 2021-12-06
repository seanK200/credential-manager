import os, sys, subprocess

# CONSTS
VENV_NAME = 'env'
DATA_DNAME = 'data'

RESPONSE_YES = ['yes', 'y']
RESPONSE_NO = ['no', 'n']

PROMPT_INIT = "Preparing to setup Pypass on your system..."
PROMPT_INIT_VENV = """You are not in a Python virutal environment.
Do you want to intialize and activate a new Python virutal environment before installing dependencies?"""
PROMPT_RUN_AFTER_VENV_ACTIVATE = f"""A new Python virtual environment '{VENV_NAME}' was sucessfully created.
Activate the new Python virtual environment with 'source {VENV_NAME}/bin/activate' and run setup again."""
PROMPT_INSTALL_DEPS = "Continue to install dependencies?"
PROMPT_DEFAULT_YN = "Continue?"
PROMPT_EXIT = "Exiting..."

SUCCESS_SETUP = "Setup success! Run Pypass by running 'python3 pypass.py'."

ERROR_VENV_FAILED = 'Failed to initialize new virtual environment. Exiting Pypass...'
ERROR_YN_RESPONSE_INVALID = "Invalid response. Enter either 'y' or 'n' as a reponse. Please try again."
ERROR_ABORT = "Setup aborted by user."
ERROR_SETUP_FAIL = "Setup is incomplete. Please run setup again before using Pypass."

def ask_yn(prompt:str=PROMPT_DEFAULT_YN)->bool:
    """
    Ask a yes/no question to user with the given prompt and get response.
    Returns True if the user answered yes, False otherwise.
    """
    response = ''
    while not response:
        response = input(f'{prompt} (y/n)  ').lower()
        if response in RESPONSE_YES:
            return True
        elif response in RESPONSE_NO:
            return False
        else:
            print(ERROR_YN_RESPONSE_INVALID)
            response = ''

def subprc_parsecmd(cmd_str):
    cmd = [arg for arg in cmd_str.strip().split(" ")]
    for idx, arg in enumerate(cmd):
        # Substitute python or python3 calls
        if 'python' in arg:
            cmd[idx] = sys.executable
            break
    return cmd

# run command
def subprc_call(cmd_str, suppress_stdout=False, raise_on_nonzero_returncode=True):
    cmd = subprc_parsecmd(cmd_str)
    return_code = 0
    args_stdout = None
    if suppress_stdout:
        args_stdout = subprocess.DEVNULL
    try:
        subprocess.check_call(cmd, stdout=args_stdout)
    except subprocess.CalledProcessError as cpe:
        print(ERROR_VENV_FAILED)
        return_code = cpe.returncode
        if raise_on_nonzero_returncode:
            raise cpe
    finally:
        return return_code

def run_setup():
    print(PROMPT_INIT, flush=True)
    setup_success = False
    setup_continue = True
    try:
        # Check if user is already running virtual env
        in_venv = sys.prefix != sys.base_prefix

        answer_use_venv = False
        # If not, ask
        if not in_venv:
            answer_use_venv = ask_yn(PROMPT_INIT_VENV)
            if answer_use_venv:
                print()
                print("Creating a new Python virtualenv '' in the working directory...", end=" ", flush=True)
                subprc_call(f'python3 -m venv {VENV_NAME}')
                print("Success")
                print(PROMPT_RUN_AFTER_VENV_ACTIVATE)
                setup_continue = False
                # subprc_call(f'source {VENV_NAME}/bin/activate')

        # Create data directory if not exists
        dirs = os.listdir(".")
        if DATA_DNAME not in dirs:
            os.mkdir(DATA_DNAME)
        
        # Install deps
        if setup_continue and ask_yn(PROMPT_INSTALL_DEPS):
            print("Installing dependencies for pypass...", flush=True)
            subprc_call('python3 -m pip install -U pip')
            subprc_call('python3 -m pip install -U setuptools wheel')
            subprc_call('python3 -m pip install -r requirements.txt')
            print("Successfully installed dependencies for pypass!")
            # Mark installation as success
            setup_success = True
    except subprocess.CalledProcessError as cpe:
        print()
        print(f"ERROR: Subprocess '{cpe.cmd}' unexpectedly ended with exit code '{cpe.returncode}'.")
    except KeyboardInterrupt:
        print()
        print(ERROR_ABORT)
    finally:
        print()
        if not setup_success:
            print(ERROR_SETUP_FAIL)
        print(PROMPT_EXIT)

if __name__ == "__main__":
    run_setup()