#!/usr/bin/env ruby 

require 'openssl'
require 'digest'

if ARGV.length < 3
    $stderr.puts "Usage: #{$0} infile outfile key"
    exit 1
end

infile = ARGV[0]
outfile = ARGV[1]
pre_key = ARGV[2]

secret_key = Digest::MD5.digest(pre_key)[-5..-1]

plain_text = File.read(infile)
rc4 = OpenSSL::Cipher.new('RC4-40')
rc4.encrypt
rc4.key = secret_key

cipher_text = rc4.update plain_text

File.write(outfile, cipher_text)
