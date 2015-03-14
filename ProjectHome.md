# Encrypted HTML Bundle #

Ever want to email an encrypted file, but don't want to deal with the hassle of installing and setting up S/MIME or PGP?  Even worse is trying to get your recipient to do the same.  This script solves the problem by encrypting your file, and embedding it in an HTML document which will allow the recipient to decrypt and download the original file without having to install any special software.  All they need is a browser!

[Download it here.](https://drive.google.com/open?id=0Bx4iYaMcDfNCSHpxeGlhcldJZm8&authuser=0)

# How it Works #

The `encrypt_html.py` python script encrypts a file and embeds it in an HTML file called `encrypted.html`.  Just drag the file to encrypt onto the script or use the command line `encrypt_html.py <file to encrypt>`.  Enter a passphrase and the encrypted html bundle will be created.

This HTML file can be emailed or given to a recipient.  The encrypted file data and all of the computation needed to decrypt the file are in the file.  The recipient only needs to know the password.

The HTML file uses a data uri to generate the file in Firefox and Chrome.  In Internet Explorer it uses a Blob object since data uris are limited.

The encryption is AES 256 with Cypher-block Chaining.

# Compatibility #

The python script should be compatible with Python >= v2.6.  The HTML file should be compatible with Internet Explorer 10 or current versions of Chrome and Firefox.

# Issues #

The only issue with this version is that the passphrase is passed directly to the AES 256 algorithm.  AES 256 takes 32 bytes.  Thus if the passphrase is less than 32 characters it will be padded with nulls, and if the passphrase is longer than 32 bytes it will be truncated.  This is less than ideal.  In an update, the passphrase will be hashed first before being passed to AES 256 as the key.