LfLe
====

Recover event log entries from an image by heurisitically looking for record structures.

Dependencies
------------
  - argparse (http://pypi.python.org/pypi/argparse available via easy_install/pip)

Usage
-----
Use this tool to extract event log messages from an image file by looking for things
that appear to be records.  Then, feed the resulting file into an event log viewer,
such as Event Log Explorer (http://www.eventlogxp.com/, use "direct" mode when opening).


    usage: lfle.py [-h] [-v] [-s] input_path output_path
    
    Recover event log entries from an image by heurisitically looking for record
    structures.
    
    positional arguments:
      input_path   Path to a raw (dd) image file.
      output_path  Path to write output file that contains recovered event log
                   entries.
    
    optional arguments:
      -h, --help   show this help message and exit
      -v           Print debugging messages during scanning.
      -s           Disable status messages (percent complete) during scanning.

Sample Output
-------------
    evt/LfLe - [master●] » python lfle.py "/media/truecrypt2/VM/Windows XP Professional - Service Pack 3 - TEMPLATE/Windows XP Professional - Service Pack 3-cl1.vmdk" recovered.evt
    100% complete% done
    Wrote 5413 records
    Skipped 48 records with length greater than 0x10000
    Skipped 12 records with length less than 0x30
    Skipped 14 records with invalid structure
    Skipped 1 records with invalid content

Limitations
-----------
This tool supports only EVT/WinXP style event log messages.  It does not support recovering
EVTX/Win7 style event log messages.