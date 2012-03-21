#!/usr/bin/env python
#
# Name: BssidFromPcap.py
# Decription: List unique BSSIDs from pcap capture file.
# Date: 23 Jan 2012
# Author: Brixton Cat
# Version: 0.2
#

### Import modules

import sys
from scapy.all import *

### Declare variables and constants

# Open output file
outfile = open('./Out.lst', 'w')
# Obtain pcap capture file from first arguments
capfile = sys.argv[1]
# Open pcap capture file with scapy
capture = rdpcap(capfile)
# Filter for blank MAC address: 00:00:00:00:00:00
blank = '00:' * 5 + '00'
# Blank array for unique bssids
unique = []

### Script

# Read pcap capture file
for pcks in capture:

  # If pcks is Dot11 (802.11) package
  if pcks.haslayer(Dot11Beacon):
    # Obtain MAC address from package
    bssid = pcks.addr2
  
    # If bssid is blank go to next iteration
    if bssid == blank:
      continue
	  
    # Check if exist bssid in unique array and append it
    else:
      if unique.count(bssid) == 0:
	unique.append(bssid)
	# Write bssid in outfile
	outfile.write(bssid + "\n")
	
  # Else go to next iteration
  else:
    continue

# Close output file
outfile.close()

#EOF
##EOF