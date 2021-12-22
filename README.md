# Password Manager 3
Offline/CLI password manager

## Instructions
1. Download the zip file for the code
2. Unzip the folder
3. Install the dependencies by running ```pip install -r requirements.txt```
4. Run ```main.py```

## Basic structure
![basic sctructure image](https://github.com/KaindraDjoemena/password-manager-3/blob/main/basic_diagram.jpg?raw=true)<br/>
There are other commands like ```help```, ```clear```, ```/search```, ```/delete```, ```/update```, and ```/copy``` but you can easily read the source code ```pages.py``` to figure out how it works.

## Commands
### General commands
```/display``` => Displays all saved data.<br/>
```//display``` => Displays all saved data in a descending order.<br/>
```/new``` => Makes a new card/save new data.<br/>
```/search``` => Searches for data in the database by specifying its website column.<br/>
```/delete``` => Deletes data by specifying the row's id.<br/>
```/update``` => Updates a specified id's column.<br/>
```/settings``` => User configuration page.<br/>
```help``` => Lists all of the commands.<br/>
```clear``` => Clear the terminal.<br/>
```exit```/```quit``` => Terminates the program.<br/>

### Input commands
```//c``` => Gets out of an input field.<br/>
```random``` => Generates a 20 character long random password.<br/>
```random LENGTH``` => Specifies the character count of the random password.<br/>
```email``` => Inputs the input field with the default email address.<br/>

![basic sctructure image](https://github.com/KaindraDjoemena/password-manager-3/blob/main/command_examples.JPG?raw=true)
