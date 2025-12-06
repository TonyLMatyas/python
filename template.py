#!/usr/bin/python

# Input
################################################################################

# Imports
########################################
import os
import datetime

# Variables
########################################

# Default Variables
HOME=os.path.expanduser("~")
FULL=os.path.realpath(__file__)
BASE=os.path.basename(__file__)

print(HOME)
print(FULL)
print(BASE)


# Current date and time
now = datetime.now()
print(now)
exit()

# Formats
formats = {
    "YYYY-MM-DD": now.strftime("%Y-%m-%d"),
    "DD-MM-YYYY": now.strftime("%d-%m-%Y"),
    "MM/DD/YYYY": now.strftime("%m/%d/%Y"),
    "Full date": now.strftime("%B %d, %Y"),
    "HH:MM:SS": now.strftime("%H:%M:%S"),
    "Custom Format": now.strftime("%Y-%m-%d %H:%M:%S"),
}

# Displaying the dates
for description, formatted_date in formats.items():
    print(f"{description}: {formatted_date}")

