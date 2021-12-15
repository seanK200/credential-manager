# PyPass
PyPass is a local password manager, for creating, managing and using credentials for various services.

## Feature Overview
* Encrypted storage of credential data
* Automatic generation of secure passwords
* Signing of database entries for tamper-proofing stored data
* Search by service name
* Support automatic login (requires `sudo`)

## Setup and Usage
Run the following command in your terminal. The script will automatically install any dependencies an run the application when it is done.
```
python run.py
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