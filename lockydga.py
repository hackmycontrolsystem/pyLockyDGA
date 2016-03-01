#!/usr/bin/python
#
# Reimplements the Locky DGA Algorithm in Python
#
# Based on the reverse engineering from Forcepoint
#
# Author: Kris Hunt <kris_hunt@Symantec.com> 
# Date: 1-March-16
# Version: 0.01
#
# Todo - Get it working properly. Right now it produces results which do 
# not align with the Locky DGA
#

from numpy import uint32
from ctypes import *
from datetime import datetime
from rotate import __ROR4__, __ROL4__ # source: https://github.com/tandasat/scripts_for_RE/blob/master/rotate.py

WORD = c_ushort

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

# example, use todays date
t = datetime.now()

# build a SYSTEMTIME object using todays date from above
systemtime = SYSTEMTIME(t.year, t.month, t.weekday(), t.day, t.hour, t.minute, t.second, (t.microsecond/1000)) 

for z in range(8):
	print LockyDGA(z, 7, systemtime)
