# FlipperAmeeboNFCFixer
A python script for fixing ameebo nfc files for the flipper zero

**NOTE:** This is intended to be used on flipper zero .nfc files only. Bin files are not supported.

**Usage:**

1. Dry run (safe preview):
`python3 FlipperAmeeboNFCFixer.py ./ameebo_files`

2. Fix any detected problems:
`python3 FlipperAmeeboNFCFixer.py ./ameebo_files --fix`

3. Fix only passwords and PACK (skip UID and BCC):
`python3 FlipperAmeeboNFCFixer.py ./ameebo_files --fix --no-uid --no-bcc`

4. Fix everything except UID generation:
`python3 FlipperAmeeboNFCFixer.py ./ameebo_files --fix --no-uid`


## Special Thanks

I would like to thank [@equipter](https://github.com/equipter) for all the help understanding 0x88 in the 4th position of the UID as well as CT anaylsis, BCC0 and BCC1 calculations
