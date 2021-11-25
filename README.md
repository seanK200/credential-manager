# Python Credential Manager
Python Credential Manager is a local password manager, for creating, managing and using credentials for various services.

## Features
* Encrypted storage of credential data
* Password protection of software
* Automatic generation of secure passwords
* Search by domain name

## Installation
1. 

## Usage
### 1. Adding new credentials

**Usage**
```
>> new
```

**Sample output:**
```
===== Adding new credential entry =====

[1/3] Enter service/domain name: github.com
[2/3] Enter your ID (leave blank if there is none): seanK200
[3/3] Password
<Options>
1. Generate new secure password (recommended)
2. Enter a pasword yourself

Choose option (Enter 1 or 2): 1
```
```
Generating password...
The following entry will be created.
Please confirm your input.

======== ENTRY 234 ========
 * service/domain name: github.com
 * ID: seanK200
 * PW: zxCvl&*aSd98n$
===========================

Is the information above correct (y/n)? y
Saving...

--> The new password has been copied to your clipboard.
```

### 2. **view**: Print credential information on screen

**Usage**
```
>> view <domain-name>
```

### 3. **edit**: Edit credential information of particular entry
**Usage**
```
>> edit <domain-name>
```

### 4. **delete**: Delete credential information
**Usage**
```
>> delete <domain-name>
```

### 5. **list**: List all data
```
>> list
```

### 6. **lock**: Encrypts the datafile, and prohibit data access
```
>> lock
```