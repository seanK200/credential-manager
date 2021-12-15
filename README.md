# PyPass
PyPass is a multi-user, interactive credentials manager with local encrypted storage, database signing, and automated logins.

## Feature Overview
* Encrypted storage of credential data
* Automatic generation of secure passwords
* Signing of database entries for tamper-proofing stored data
* Search by service name
* Support automatic login (requires `sudo`)

## Setup
Run the following command in your terminal. The script will automatically install any dependencies.
```
python pypass_setup.py
```

## Usage
Run the program by invoking the runner code. Run it in `sudo` for full feature support (automatic login)
```
sudo python3 run.py
```

## Initial Run
On the first run, enter a username and a master password, to lock/unlock data you store on PyPass.

## Features
Use the arrow keys to select a feature and ENTER to execute.
```
Choose action:
> View entry
  Add new entry
  Edit entry
  Delete entry
  --------------
  Delete user
  Quit
```

## License
* MIT as the overall license (See LICENSE)
* Multiple other secondary permissive or copyleft linceses for third-party components. Check all license files in the depedent projects' repositories (linked below) before usage of pypass.
  * [pyca/cryptography](https://github.com/pyca/cryptography): Either Apache or BSD 3-Clause
  * [boppreh/keyboard](https://github.com/boppreh/keyboard): MIT
  * [asweigart/pyperclip](https://github.com/asweigart/pyperclip): BSD 3-Clause
  * [pwaller/pyfiglet](https://github.com/pwaller/pyfiglet): MIT
  * [willmcgugan/rich](https://github.com/willmcgugan/rich): MIT
  * [CITGuru/PyInquirer](https://github.com/CITGuru/PyInquirer): MIT