# Password Manager 3
Offline/CLI password manager

## Encryption/hashing
- Uses SHA256 for hashing.
- Uses the user's master password and converts it into their encryption key with PBKDF2.

## Basic structure
![basic sctructure image](https://github.com/KaindraDjoemena/password-manager-3/blob/main/basic_diagram.jpg?raw=true)<br />
There are other commands like ```help```, ```clear```, ```/search```, ```/delete```, ```/update```, and ```/copy``` but you can easily read the source code ```pages.py``` to figure out how it works.
