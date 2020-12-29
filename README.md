# Password cracking exercise

## Overview
1. First encrypt a file using any 5 hex characters as a key using the rc4_40_encrypt.rb program. Currently this is a 20-bit exhaust. 
1. For the password guessing program, use Ractors to calculate in parallel. Use N-1 CPUs to guess. Use an entropy score to score the output each time. If any
result is positive, pass messages to all the other Ractors and quit. 
1. Then do the same, but pick a random word out of /usr/share/dict/words to be the password. Note the time difference in cracking

## TODO
1. speed up the entropy calculation using Rust and Helix
