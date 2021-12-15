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