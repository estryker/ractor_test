#!/usr/bin/env ruby 

require 'openssl'
require 'digest'

if ARGV.length < 3
    $stderr.puts "Usage: #{$0} infile outfile key (5 hex chars)"
    exit 1
end

infile = ARGV[0]
outfile = ARGV[1]
pre_key = ARGV[2]

# MD5.digest can't seem to run in a Ractor so just take the first 5 hex chars. 
# TODO: guarantee hex chars ...
secret_key = "aaaaa" 
if pre_key.downcase.match(/^[0-9a-f]{5}$/) # Digest::MD5.digest(pre_key)[-5..-1]
    secret_key = pre_key.downcase
else
    $stderr.puts "Key must be 5 hex chars"
    exit(2)
end

plain_text = File.read(infile)
rc4 = OpenSSL::Cipher.new('RC4-40')
rc4.encrypt
rc4.key = secret_key

cipher_text = rc4.update plain_text

File.write(outfile, cipher_text)
