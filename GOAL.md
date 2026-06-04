# PHP library that authenticates image files 
TIF format to start with
It's called "Chain of Custody".

# It has several functions:
## Create a signature
Process:
- Receive a TIF image file as input
- Create a checksum of it.
- Store that checksum as a tag field into the TIF file.
- Store in a mysql database the checksum and the name of the author.
- If the file already contained a signature, verify it, then create a link in the database between the new signature and the previously stored one.
- Return the new signature hash.

## Check a signature
Process:
- Receive a TIF file as input.
- Find the signature tag.
- Look it up in the database. 
- If it's found, remove it from the file, create a signature of the file as above, and compare to the signature tag. 
- If they're the same, the file is authenticated. If not, the file is not authenticated.

## Check chain of custody
Process:
- Receive a TIF file as input.
- Check the validity of the signature.
- Find it in the database. Then return the chain of signatures stored in the database a links between signatures.

# Deliverables 
The database parameters are stored in a config file. 
Create the PHP library handling the functionality above.
Create the schema of the database. 
Create a CLAUDE.md and a description of the new image chain of custody standard.
