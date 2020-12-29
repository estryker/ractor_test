#!/usr/bin/env ruby
require 'openssl'
require 'digest'


if ARGV.length < 2
    $stderr.puts "Usage: #{$0} infile outfile"
    exit 1
end

infile = ARGV[0].dup.freeze
outfile = ARGV[1].dup.freeze

def entropy(s)
    counts = Hash.new(0)
    s.each_char { |c| counts[c] += 1 }
  
    counts.values.reduce(0) do |entropy, count|
      freq = count / s.length.to_f
      entropy - freq * Math.log2(freq)
    end
end
  
# Find the best answer assuming that we are cracking a password that 
# was specified in hex instead of using the full byte range. 
# Using rc4_40, this will be a 20 bit exhaust. 
def best_answer(step:, remainder:,cipher_text:, cipher:, key_byte_size:)
  
  best_key = "00000"
  best_score = 8.0
  best_decrypt = cipher_text
  
  (remainder .. 2**(key_byte_size * 4)).step(step).each do | putative_key_num |
    putative_key = sprintf("%05x", putative_key_num)[0...key_byte_size] # Digest::MD5.digest(putative_key_num.to_s(16))[-5..-1]
    
    # this initializes for decryption
    cipher.decrypt
    cipher.key = putative_key
    putative_plain = cipher.update(cipher_text)

    score = entropy(putative_plain)
    
    # Since we are using entropy, lower is better. 8.0 entry on bytes means completely random
    if score < best_score
        best_key = putative_key
        best_score = score
        best_decrypt = putative_plain
    end

  end
  return [best_key, best_score, best_decrypt]
end

# send/ receive  : push type  send to handle, receive from external 
# yield / take  : pull type - yield to external, take from handle 
pipe = Ractor.new do 
  loop do
      Ractor.yield  Ractor.receive
  end
end

RN = 7
rs = RN.times.map{|i|
  Ractor.new pipe, infile, i, RN do |pipe, infile, i, rn |
    rc4 = OpenSSL::Cipher.new('RC4-40')
    model = [1.1022717747569128, -1.2539935875616006, -1.0715412114558136, 0.38719776947991313, 1.6845307000026097, -0.7395933064620372, -0.8554740185121767, 1.1968470166179053, 0.8013343423198935, -5.039898589649604, -1.7287413912185645, 0.12571441052969412, -0.7597030032711771, 0.8211626750437087, 0.9027128482015736, -1.6177990626724998, -6.749308461295249, 0.1998478612902792, 0.6214967405755889, 1.3658406631655162, -0.546191980118989, -2.6368337320368367, -0.4744424032799319, -6.230841372361, -1.28104218528319, -6.749308461295249].freeze
    cipher_text = File.read(infile)
    
    pipe.send(best_answer(step: rn, remainder: i, cipher_text: cipher_text, cipher: rc4, key_byte_size: 5))
  end
}

  RN.times.map {
    pipe.take
}.each {|x| puts "#######\n" + x.join("\t") + "\n\n"}
