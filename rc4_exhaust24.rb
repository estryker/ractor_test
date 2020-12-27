#!/usr/bin/env ruby
require 'openssl'
require 'digest'

if ARGV.length < 2
    $stderr.puts "Usage: #{$0} infile outfile"
    exit 1
end

infile = ARGV[0].dup.freeze
outfile = ARGV[1].dup.freeze

Model = [1.1022717747569128, -1.2539935875616006, -1.0715412114558136, 0.38719776947991313, 1.6845307000026097, -0.7395933064620372, -0.8554740185121767, 1.1968470166179053, 0.8013343423198935, -5.039898589649604, -1.7287413912185645, 0.12571441052969412, -0.7597030032711771, 0.8211626750437087, 0.9027128482015736, -1.6177990626724998, -6.749308461295249, 0.1998478612902792, 0.6214967405755889, 1.3658406631655162, -0.546191980118989, -2.6368337320368367, -0.4744424032799319, -6.230841372361, -1.28104218528319, -6.749308461295249].freeze

# reducing the key space to 2**24 for demonstration purposes
#rand_key = rand(2**24)


def score_decrypt(decrypt_string,model_array)
  decrypt_string.downcase.each_char.select {|c| ('a'..'z').include? c}.reduce(0) { |memo,char| memo += model_array[char.ord - 'a'.ord] }
end
  
def top_answer(step, remainder,cipher_text, cipher, key_byte_size, plaintext_byte_model)
  
  top_key = nil
  top_score = -99
  top_decrypt = ""
  (remainder .. 2**24).step(step).each do | putative_key |
    # this initializes for decryption
    cipher.decrypt
    cipher.key = putative_key
    putative_plain = rc4.update(cipher)
    score = score_decrypt(putative_plain, plaintext_byte_model)
    if score > top_score
        top_key = putative_key
        top_score = score
        top_decrypt = putative_plain
    end
    if top_score > 0.0
        break
    end
  end
  return [top_key, top_score, top_decrypt]
end

# send/ receive  : push type
# yield / take  : pull type 
pipe = Ractor.new do 
  loop do
      Ractor.yield  Ractor.receive
  end
end

# TODO: how to have all of the loops to stop when one of them returns a score above 0.0
RN = 7
rs = RN.times.map{|i|
  Ractor.new pipe, infile, i do |pipe, infile, i|
    rc4 = OpenSSL::Cipher.new('RC4-40')
    cipher_text = File.read(infile)
    pipe.send(top_answer(step: RN, remainder: i, cipher_text: cipher_text, cipher: rc4, key_byte_size: 5, plaintext_byte_model: Model))
  end
}

  RN.times.map{
    pipe.take
}.each {|x| puts "#######\n" + x.join("\t") + "\n\n"}
