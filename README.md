# CredentialChecker

This simple credential checker can be used to identify if your email account or password has been
detected in any public breaches. 
This tool leverages the HIBP database to find compromised email accounts and passwords.
Current Paste sources : Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl,OptOut.
When using the password checker (option 2) your password is NOT transmitted, it is hashed (SHA1) AND only the
first 5 characters are used to verify if it is available online.You can verify this in the source code."

Usage : run the program with 

python credentialchecker.py
python3 credentialchecker3.py

Python version :

Python 2.7.10 - credentialchecker.py 
python 3.6.5  - credentialchecker3.py


Credits to haveibeenpwned.com for providing the data. 



