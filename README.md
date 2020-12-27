# Password cracking exercise

## Overview
1. First pick a random number between 1, 2 ** 32.  Encrypt a file using that as the RC4 key and save it off (in hex) to be checked at the end. 
1. For the password guessing program, use Ractors to calculate in parallel. Use N-1 CPUs to guess. Use the byteModel to score the output each time. If any
result is positive, pass messages to all the other Ractors and quit. 
1. Then do the same, but pick a random word out of /usr/share/dict/words to be the password. Note the time difference in cracking

