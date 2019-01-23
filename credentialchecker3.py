#!/usr/bin/python
import requests 
import sys 
import json
import getpass
import hashlib
from pprint import pprint

######==============================================================================######
##This tool leverages the HIBP database to find compromised email accounts and passwords##
######==============================================================================######
def hibpEmailCheck(user_account):
    #HIBP APIv2 requires a user agent to be specified. 
    if len(user_account) != 0:
        account = user_account
        url1 = "https://haveibeenpwned.com/api/v2/breachedaccount/"+ account   
        header = {'User-Agent': 'My User Agent 1.0'}
        response1 = requests.get(url1, headers=header)  
        content1 = response1.content.decode("utf-8")
        if response1.status_code == 200:
            content1 = json.loads(content1)
            pprint (content1)
        elif response1.status_code == 404:
            print ("Account details haven't been leaked in any known breach.")
        elif response1.status_code == 403:
            print ("No user agent was specified")       
    else:
        print ("enter a email address")
        sys.exit(1)

def hibpPasteCheck(user_account):
    #The paste service the record was retrieved from. Current values are: Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl, OptOut
    if len(user_account) != 0:
        account = user_account
        url2 = "https://haveibeenpwned.com/api/v2/pasteaccount/"+ account 
        header = {'User-Agent': 'My User Agent 1.0'}
        response2 = requests.get(url2, headers=header)
        content2 = response2.content.decode("utf-8")
        if response2.status_code == 200:
            content2 = json.loads(content2)
            pprint (content2)
        elif response2.status_code == 404:
            print ("Account details haven't been detected in any pastes.")
        elif response2.status_code == 403:
            print ("No user agent was specified")
    else:
        print ("enter a email address")
        sys.exit(1)

def hashGen():
    #get the user password, and SHA1 it 
    password = getpass.getpass().encode("utf-8")
    hashpwd = hashlib.sha1(password).hexdigest()
    return hashpwd

def hashCheckHIBP():
    hash_list = []
    hashpwd = hashGen().upper()
    first_five_hash_chars = hashpwd[0:5]
    remaining_hash_chars = hashpwd[5:]
    print("\nThe SHA1 hash of your password is "+hashpwd)
    print("\nThe hash PREFIX is "+first_five_hash_chars)
    #print("\nThe hash SUFFIX is "+remaining_hash_chars)
    print ("\nchecking for matches...")
    content = hibpHashCheckAPIRequest(first_five_hash_chars).decode("utf-8")
    length = content.count('\n')
    #print ("\nThere were " + str(length) + " hash SUFFIXES that matched")
    list_content = content.split("\r\n")
    
    #seperating the count from the hash
    for items in list_content:
        head, sep, tail = items.partition(':')
        list_content = (first_five_hash_chars + head).upper()
        hash_list.append(list_content)

    if hashpwd in hash_list:
        print ("\nYour password hash has been found in the DB ---- " + hashpwd)
        print ("Change THIS password immediately!!\n\n")   
    else:
        print ("Your password hash has not been found in the DB ")

def hibpHashCheckAPIRequest(first_five_hash_chars):
    #method to run the api request
    url = "https://api.pwnedpasswords.com/range/"+first_five_hash_chars
    response = requests.get(url) 
    content = response.content
    return content

def getUserChoice():
    print ("This tool leverages the HIBP database to find compromised email accounts and passwords.\nCurrent Paste sources : Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl,\n OptOut.\nWhen using the password checker (option 2) your password is NOT transmitted, it is hashed (SHA1) AND only the first 5 characters are used to verify if it is available online.\n You can verify this in the source code.\n")
    while True:
        user_input = input("USAGE: Press Enter after your choice\n\nEnter\n\t'1' for email check \n\t'2' for password check \n\t'3' to EXIT\n")
        if user_input == '1':
            user_account = input("\nEnter email ID to check\n")
            hibpEmailCheck(user_account)
            hibpPasteCheck(user_account)
        elif user_input == '2':
            hashCheckHIBP()
        elif user_input == '3':
            print ("QUITTING !")
            sys.exit()
        else:
            print ("\nInvalid Input")
        
        

def main():
    getUserChoice()
    
if __name__ == '__main__':
    main()
