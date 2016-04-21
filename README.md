# FabulousCDN
A soon-to-be greatest CDN application made in python the world has ever known.

This is still a work in progress. As such, it would be REALLY helpful if you don't 
fork this...because I don't have an actual name for this project yet, and apparently
renaming the project after people fork it may or may not cause problems if I rename it.

Most of the options can be used with each other. You can dump in seeddb, decTitleKey, 
encTitleKey, and the 3dsdb xml which will all get concatenated into a database which
can be filtered with the available options and printed out with user-specified formatting.


These HAVEN'T been implemented yet:
- 3ds/cia building
- GUI mode
- Parsing title metadata from Nintendo samurai server
- Parsing crypto seed from Nintendo ninja server
- Downloading app data
- Decrypting app data
- Checking decrypted key against app data (pycrypto stuff)
- Quick and easy localization (gettext)
- XML generation (3dsdb style, but altered "type" because theirs is next to useless)

These HAVE been implemented:
- Read decTitleKeys.bin (comma separated for multiple files)
- Read encTitleKeys.bin (comma separated for multiple files)
- Read ticket.tik files (comma separated for multiple files)
- Read seeddb.bin (comma separated for multiple files)
- Read ticket.db (comma separated for multiple files)
- Read 3dsdb xml (comma separated for multiple files)
- Read from certain online sources for decTitleKeys.bin, encTitleKeys.bin, and the 3dsdb xml
- Filtering by region, encrypted, decrypted, crypto_seed, title_id, type, title name (this 
    one is literally worthless atm since you have to be spot on with the name in order to 
    filter with this)
- Accepts title_id, decrypted title key, encrypted title key, crypto seed, common key
- Export decTitleKeys.bin (concatenated or game-specific)
- Export encTitleKeys.bin (concatenated or game-specific)
- Export ticket.tik (game-specific only)
- Export seeddb.bin (concatenated or game-specific)
- Print out concatenated database with user-specified formatting (use double quotes, not 
    single, argparse doesn't like apostrophes). 
    Default formatting: "| %title_name | %title_id | %serial | %region | %size | %type | %publisher | %dec_key | %enc_key | %crypto_seed | %common_key |"
