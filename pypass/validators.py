import re

from params import *
from consts import *

# ######### GLOBALS #########
globals_user_pw = ''

# ######### VALIDATORS #########

def validate_entry_name(entry_name, verbose=True):
    if not entry_name:
        if verbose:
            return ERROR_NEW_ENTRY_NAME_EMPTY
        return False
    if len(entry_name) > 512:
        if verbose:
            return ERROR_NEW_ENTRY_NAME_TOO_LONG
        return False
    return True

def validate_user_id(user_id, verbose=True):
    # Too long
    if len(user_id) > USER_ID_MAX_LEN:
        if verbose:
            return ERROR_NEW_ID_TOO_LONG.format(USER_ID_MAX_LEN)
        return False
    # Unsupported chars
    for ch in user_id:
        if ch not in PRINTABLE:
            if verbose:
                return ERROR_ID_UNSUPPORTED_CHARS.format(ch)
            return False
    return True

def validate_user_pw(user_pw, verbose=True, strict=False):
    global globals_user_pw
    # Too short
    if len(user_pw) < USER_PW_MIN_LEN:
        if verbose: 
            return ERROR_PW_TOO_SHORT.format(USER_PW_MIN_LEN)
        return False
    # Too long
    if len(user_pw) > USER_PW_MAX_LEN:
        if verbose: 
            return ERROR_PW_TOO_LONG.format(USER_PW_MAX_LEN)
        return False
    # Unsupported chars
    for ch in user_pw:
        if ch not in PRINTABLE:
            if verbose:
                return ERROR_PW_UNSUPPORTED_CHARS.format(ch)
            return False
    globals_user_pw = user_pw
    return True

def validate_user_pw_confirm(user_pw_confirm, verbose=True):
    if globals_user_pw != user_pw_confirm:
        if verbose:
            return ERROR_PW_CONFIRM
        return False
    return True

def validate_entry_url(entry_url:str, verbose=True):
    # Too long
    if len(entry_url) > 256:
        if verbose:
            return "A URL must be shorter than 256 characters."
        return False

    # Not a url
    url_pattern = r"[((http(s)?)|(ftp(s)?)):\/\/(www\.)?a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)"
    url_match = re.match(url_pattern, entry_url)
    if not url_match:
        if verbose:
            return "Please enter a valid URL."
        return False

    return True