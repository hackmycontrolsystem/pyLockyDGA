#!/usr/bin/python
#
# Reimplements the Locky DGA Algorithm in Python
#
# Based on the reverse engineering from Forcepoint
#
# Author: Kris Hunt <kris_hunt@Symantec.com> 
# Date: 1-March-16
# Version: 0.1
#

from numpy import uint32,seterr
from ctypes import *
from datetime import datetime
from rotate import __ROR4__, __ROL4__ # source: https://github.com/tandasat/scripts_for_RE/blob/master/rotate.py

WORD = c_ushort

# Locky DGA seed. Forcepoint claim this is now "9"
SEED = 9

# implements the Windows SYSTEMTIME structure for completeness
# based on: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724950%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
class SYSTEMTIME(Structure):
	_fields_ = [("wYear", WORD),
		    ("wMonth", WORD),
		    ("wDayOfWeek", WORD),
		    ("wDay", WORD),
		    ("wHour", WORD),
		    ("wMinute", WORD),
		    ("wSecond", WORD),
		    ("wMilliseconds", WORD)]

# implements the Locky DGA algorithm in Python
# C source from: 
# https://blogs.forcepoint.com/security-labs/lockys-new-dga-seeding-new-domains
def LockyDGA(pos, cfgseed, SystemTime):

	# supress numpy integer overflow warnings, we desire this behaviour
	seterr(over='ignore')
	
	domain = []
	
	modConst1 = 0xb11924e1
	modConst2 = 0x27100001
	modConst3 = 0x2709a354
	i = 0
	seed = cfgseed

	tldchars = "rupweuinytpmusfrdeitbeuknltf"

	# Shift the dates
	modYear = uint32(__ROR4__(modConst1 * (SystemTime.wYear + 0x1BF5), 7))
	modYear = uint32(__ROR4__(modConst1 * (modYear + seed + modConst2), 7))
	modDay = uint32(__ROR4__(modConst1 * (modYear + (SystemTime.wDay >> 1) + modConst2), 7))
	modMonth = uint32(__ROR4__(modConst1 * (modDay + SystemTime.wMonth + modConst3), 7))

	# Shift the seed
	seed = uint32(__ROL4__(seed, 17))

	# Finalize Modifier
	modBase = uint32(__ROL4__(pos & 7, 21))

	modFinal = uint32(__ROR4__(modConst1 * (modMonth + modBase + seed + modConst2), 7))
	modFinal = uint32(modFinal + 0x27100001)
 
	# Length without TLD (SLD length)
	genLength = modFinal % 11 + 5;

	if genLength:
		# Generate domain string before TLD
		while i < genLength:
			x = uint32(__ROL4__(modFinal, i))
			y = uint32(__ROR4__(modConst1 * x, 7))
			z = uint32(y + modConst2)

			modFinal = z
			domain.append(chr(z % 25 + 97)) # Keep within lowercase a-z range
			i += 1
 
		# Add a '.' before the TLD
		domain.append('.')
 
		# Generate the TLD from a hard-coded key-string of characters
		x = uint32(__ROR4__(modConst1 * modFinal, 7))
		y = uint32((x + modConst2) % ( (len(tldchars)) / 2 ))
 
		domain.append(tldchars[2 * y])
		domain.append(tldchars[2 * y + 1])

	return "".join(domain)

if __name__ == "__main__":

	print "[*] Locky DGA Generator" 
	year = raw_input("Enter the year to generate for [2016] > ")

	if not year:
		year = 2016
	else:
		try: 
			year = int(year)
		except:
			print "[-] Year should be an integer value."
			quit()

	month= raw_input("Enter the month to generate for [3] > ")

	if not month:
		month = 3
	else:
		try: 
			month = int(month)
		except:
			print "[-] Month should be an integer value."
			quit()

	day = raw_input("Enter the month to generate for [1] > ")

	if not day:
		day = 1
	else:
		try: 
			day = int(day)
		except:
			print "[-] Day should be an integer value."

	systemtime = SYSTEMTIME(year, month, 0, day, 0, 0, 0, 0) 

	for z in range(8):
		print LockyDGA(z, SEED, systemtime)
