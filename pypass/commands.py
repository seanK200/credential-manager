# Python standard libraries
import platform, webbrowser, time

# 3rd parties
import pyperclip as pc
import keyboard as kb

from PyInquirer import prompt, Separator

# Locals
from pypass.helpers import *
from pypass.consts import *
from pypass.generator import generate_strong_random_pw
from pypass.viewer import *
from pypass.validators import *

MODIFIER_KEY = 'control' # Windows, linux
if platform.system() == 'Darwin':
    MODIFIER_KEY = 'command' # macOS

def parse_cmd_args(cmd_str):
    """Parse command name and arguments from user input"""
    cmd_str = cmd_str.strip().split(" ")
    cmd = cmd_str[0]
    pos_args = [] # Positional arguments
    flags = [] # Flags

    if len(cmd_str) > 1:
        args = cmd_str[1:]
        for arg in args:
            if arg[0:2] == '--' or arg[0] == '-':
                flags.append(arg)
            else:
                pos_args.append(arg)

    return cmd, pos_args, flags

def prompt_search_query():
    """
    Prompt user for a search query
    """
    query = ''
    while not query:
        query = input(PROMPT_SEARCH_QUERY).strip()
        # Query too short
        if len(query) < SEARCH_QUERY_MIN_LEN:
            print(ERROR_VIEW_QUERY_TOO_SHORT.format(SEARCH_QUERY_MIN_LEN))
            query = ''
        elif len(query) > SEARCH_QUERY_MAX_LEN:
            print(ERROR_VIEW_QUERY_TOO_SHORT.format(SEARCH_QUERY_MAX_LEN))
            query = ''
    return query

def run_login_wizard(user_auth, query:str='', *, entry_id:int=0):
    try:
        if entry_id:
            credential = get_entry_by_id(user_auth, entry_id, to_dict=True)
        else:
            credential = get_one_entry(user_auth, query, to_dict=True)
    except sqlite3.DatabaseError:
        return False
    
    if not credential:
        # Stop if not found
        return False
    
    user_id = user_auth.decrypt(credential['user_id']).decode(HASH_ENCODING)
    user_pw = user_auth.decrypt(credential['user_pw']).decode(HASH_ENCODING)
    url = credential['url']
    
    if url:
        # Copy URL, wait for user to paste it in
        print(PROMPT_LOGIN_WIZARD_1_URL, end="")
        time.sleep(1)
        webbrowser.open(url)
        input()
    
    # Wait for user to reach login page
    print(PROMPT_LOGIN_WIZARD_2_ID)
    pc.copy(user_id)
    kb.wait('tab')
    
    # Enter the ID, PW, and hit the enter key
    kb.press_and_release(f"shift+tab, {MODIFIER_KEY}+v, tab")
    kb.write(user_pw)
    kb.press_and_release('enter')
    
    # Clean up
    user_id = ''
    user_pw = ''
    pc.copy('PyPass')

    return True

def run_view(user_auth):
    credential = get_one_entry(user_auth, prompt_search_query(), decrypt=True, to_dict=True)
    if not credential:
        return False
    
    print_credential(user_auth, credential)
    actions = [
        'Copy password',
        'View password',
        'Login Wizard',
        Separator(),
        'Done'
    ]
    action_question = [
        {
            'type': 'list',
            'name': 'chosen_action',
            'message': 'What do you want to do with this entry?',
            'choices': actions
        }
    ]
    answer = prompt(action_question)
    chosen_action = answer['chosen_action']

    if chosen_action == 'Copy password':
        user_pw = user_auth.decrypt(credential['user_pw']).decode(HASH_ENCODING)
        pc.copy(user_pw)
        print(PROMPT_PASSWORD_COPIED)
    elif chosen_action == 'View password':
        print_credential(user_auth, credential, show_pw=True)
    elif chosen_action == 'Login Wizard':
        run_login_wizard(user_auth, entry_id=credential['entry_id'])
    
    return True

def run_edit(user_auth):
    # show_pw = False
    credential = get_one_entry(user_auth, prompt_search_query(), decrypt=True, to_dict=True)
    if not credential:
        return False
    
    # Make edit choices
    edit_choices = []
    name = credential["name"]
    d_user_id = credential["user_id"]
    d_user_pw = "****"
    # if show_pw:
    #     d_user_pw = " (" + user_auth.decrypt(credential["user_pw"]).decode(HASH_ENCODING) + ")"
    url = credential["url"]
    edit_choices.append({
        'name': f"Name ({name})",
        'value': 'name'
    })
    edit_choices.append({
        'name': f"ID ({d_user_id})",
        'value': 'user_id'
    })
    edit_choices.append({
        'name': "Password",
        'value': 'user_pw'
    })
    edit_choices.append({
        'name': f"URL ({url})",
        'value': 'url'
    })

    def edit_confirmed(answers):
        return answers['confirmed'] == 'Yes'
    def edit_name(answers):
        return edit_confirmed(answers) and 'name' in answers['field_to_edit']
    def edit_id(answers):
        return edit_confirmed(answers) and 'user_id' in answers['field_to_edit']
    def edit_pw(answers):
        return edit_confirmed(answers) and 'user_pw' in answers['field_to_edit']
    def edit_pw_generate(answers):
        return edit_pw(answers) and answers['new_pw_options'] == 'generate'
    def edit_pw_manual(answers):
        return edit_pw(answers) and answers['new_pw_options'] == 'manual'
    def edit_url(answers):
        return edit_confirmed(answers) and 'url' in answers['field_to_edit']

    edit_questions = [
        {
            'type':'list',
            'name':'confirmed',
            'message':'Do you wish to edit this entry?',
            'choices':[
                'Yes',
                'No, quit command.'
            ]
        },
        {
            'type': 'checkbox',
            'name': 'field_to_edit',
            'message': 'Choose a field to edit:',
            'choices': edit_choices,
            'when': edit_confirmed
        },
        {
            'type': 'input',
            'name': 'new_name',
            'message': 'Enter a new name:',
            'when': edit_name,
            'validate': validate_entry_name
        },
        {
            'type': 'input',
            'name': 'new_id',
            'message': 'Enter a new ID:',
            'when': edit_id,
            'validate': validate_user_id
        },
        {
            'type': 'list',
            'name': 'new_pw_options',
            'message': 'New password options:',
            'when': edit_pw,
            'choices': [
                {
                    'name': 'Generate a strong new password',
                    'value': 'generate'
                },
                {
                    'name': 'Manually create one',
                    'value': 'manual'
                }
            ]
        },
        {
            'type': 'password',
            'name': 'new_pw',
            'message': 'Enter a new password:',
            'when': edit_pw_manual,
            'validate': validate_user_pw,
        },
        {
            'type': 'password',
            'name': 'new_pw_confirm',
            'message': 'Confirm password (enter again):',
            'when': edit_pw_manual,
            'validate': validate_user_pw_confirm
        },
        {
            'type': 'input',
            'name': 'new_url',
            'message': 'Enter a new URL:',
            'when': edit_url,
            'validate': validate_entry_url
        }
    ]

    # Print found credentials
    print_credential(user_auth, credential)
    
    # Ask user
    answers = prompt(edit_questions)

    if 'confirmed' not in answers:
        raise KeyboardInterrupt

    # If user did not confirm
    if not answers['confirmed']:
        print("Edit cancelled by user. Changes are not saved.")
        return False

    # Auto generate if needed
    if edit_pw_generate(answers):
        answers['new_pw'] = generate_strong_random_pw()

    # Deep copy
    new_credential = {}
    for k, v in credential.items():
        new_credential[k] = v
    
    # Add quotation marks to fields that will be printed
    new_credential['name'] = "'" + credential['name'] + "'"
    new_credential['user_id'] = "'" + d_user_id + "'"
    new_credential['user_pw'] = "'" + d_user_pw + "'"
    new_credential['url'] = "'" + credential['url'] + "'"

    if edit_name(answers):
        new_credential['name'] += " >> '" + answers['new_name'] + "'"
    else:
        answers['new_name'] = ''
    if edit_id(answers):
        new_credential['user_id'] += " >> '" + answers['new_id'] + "'"
    else:
        answers['new_id'] = ''
    if edit_pw(answers):
        new_credential['user_pw'] += " >> '" + answers['new_pw'] + "'"
    else:
        answers['new_pw'] = ''
    if edit_url(answers):
        new_credential['url'] += " >> '" + answers['new_url'] + "'"
    else:
        answers['new_url'] = ''
    
    print_credential(user_auth, new_credential, show_pw=True)

    edit_confirm_question = [
        {
            'type': 'confirm',
            'name': 'edit_confirmed',
            'message': 'Save changes?'
        }
    ]

    edit_confirmed = prompt(edit_confirm_question)['edit_confirmed']
    
    # User abort
    if not edit_confirmed:
        print("Edit cancelled by user. Changes are not saved.")
        return False

    # Update DB
    db_update_entry(user_auth, entry_id=credential['entry_id'],\
        name=answers['new_name'], user_id=answers['new_id'], \
            user_pw=answers['new_pw'], url=answers['new_url'])
    return True

def run_new(user_auth):
    print("Adding new credential entry...")
    new_questions = [
        {
            'type': 'input',
            'name': 'new_name',
            'message': 'Enter a new name:',
            'validate': validate_entry_name
        },
        {
            'type': 'input',
            'name': 'new_id',
            'message': 'Enter a new ID:',
            'validate': validate_user_id
        },
        {
            'type': 'list',
            'name': 'new_pw_options',
            'message': 'New password options:',
            'choices': [
                {
                    'name': 'Generate a strong new password',
                    'value': 'generate'
                },
                {
                    'name': 'Manually create one',
                    'value': 'manual'
                }
            ]
        },
        {
            'type': 'password',
            'name': 'new_pw',
            'message': 'Enter a new password:',
            'validate': validate_user_pw,
            'when': lambda answers: answers['new_pw_options'] == 'manual'
        },
        {
            'type': 'password',
            'name': 'new_pw_confirm',
            'message': 'Confirm password (enter again):',
            'validate': validate_user_pw_confirm,
            'when': lambda answers: answers['new_pw_options'] == 'manual'
        },
        {
            'type': 'input',
            'name': 'new_url',
            'message': 'Enter a new URL:',
            'validate': validate_entry_url
        }
    ]
    
    # Ask user
    new_answers = prompt(new_questions)
    if 'new_name' not in new_answers:
        raise KeyboardInterrupt
    
    print("Saving changes...")
    # Generate password if necessary
    if new_answers['new_pw_options'] == 'generate':
        new_answers['new_pw'] = generate_strong_random_pw()
    
    # Insert to DB
    add_result = db_add_entry(user_auth, new_answers['new_name'], new_answers['new_id'],\
        new_answers['new_pw'], new_answers['new_url'])
    
    if add_result:
        print("All changes successfully saved.")

    return add_result
    
def run_delete(user_auth):
    credential = get_one_entry(user_auth, prompt_search_query(), decrypt=True, to_dict=True)
    if not credential:
        # Stop if not found
        return False
    
    print_credential(user_auth, credential)

    delete_confirm_question = [
        {
            'type':'confirm',
            'name':'delete_confirm',
            'message':'Delete this entry?'
        }
    ]
    del_confirm = prompt(delete_confirm_question)['delete_confirm']
    
    if not del_confirm: return False
    result = db_delete_entry(user_auth, credential['entry_id'])
    
    return result


def prompt_commands():
    command_choices = [
        'View entry',
        'Add new entry',
        'Edit entry',
        'Delete entry',
        Separator(),
        'Quit'
    ]
    command_question = [
        {
            'type': 'list',
            'name': 'chosen_command',
            'message': 'Choose action:',
            'choices': command_choices
        }
    ]
    chosen_command = prompt(command_question)
    try:
        chosen_command = chosen_command['chosen_command']
    except KeyError:
        chosen_command = 'Quit'

    if chosen_command == 'Quit':
        raise KeyboardInterrupt
    return chosen_command

def run_commands(user_auth):
    command = prompt_commands()
    result = False
    try:
        if command == 'View entry':
            result = run_view(user_auth)
        elif command == 'Add new entry':
            result = run_new(user_auth)
        elif command == 'Edit entry':
            result = run_edit(user_auth)
        elif command == 'Delete entry':
            result = run_delete(user_auth)
        elif command == 'Login Wizard':
            result = run_login_wizard(user_auth)
        elif command == 'Quit':
            result = True
        if not result:
            print("Command failed to run.")
    except KeyboardInterrupt:
        print("Command aborted by user.")
    finally:
        return command