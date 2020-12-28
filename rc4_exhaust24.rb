#!/usr/bin/env ruby
require 'openssl'
require 'digest'


if ARGV.length < 2
    $stderr.puts "Usage: #{$0} infile outfile"
    exit 1
end

infile = ARGV[0].dup.freeze
outfile = ARGV[1].dup.freeze



# reducing the key space to 2**24 for demonstration purposes
#rand_key = rand(2**24)

=begin rdoc

# require 'inline'
# Can't use this: `c_entropy': ractor unsafe method called from not main ractor (Ractor::UnsafeError)

class RoughnessTest
    inline do |builder|
      builder.c <<-CCODE
  double c_entropy(char *string,int num_chars) {
    long counts[256]; 
    int i; 
    double H = 0.0; 
    
    memset(counts,0, 256 * sizeof(long));
    
    for(i=0;i<num_chars;i++){
      counts[(int) string[i] & 0xff] ++;
    }
    for(i=0;i<256;i++){
      if(counts[i] != 0) {
        H-=(double)counts[i]/num_chars * (log((double)counts[i]/num_chars) / log(2));
      }
    }
    return H;
  }
  CCODE
  
    end
  end
  Tester = RoughnessTest.new  
# to use:
score = entropy_tester.c_entropy(putative_plain, putative_plain.length)

=end


#def score_decrypt(decrypt_string,model_array)
#  decrypt_string.downcase.each_char.select {|c| ('a'..'z').include? c}.reduce(0) { |memo,char| memo += model_array[char.ord - 'a'.ord] }
#end
def entropy(s)
    counts = Hash.new(0)
    s.each_char { |c| counts[c] += 1 }
  
    counts.values.reduce(0) do |entropy, count|
      freq = count / s.length.to_f
      entropy - freq * Math.log2(freq)
    end
end
  
# def top_answer(step:, remainder:,cipher_text:, cipher:, key_byte_size:, plaintext_byte_model:)
def top_answer(step:, remainder:,cipher_text:, cipher:, key_byte_size:)
  
  top_key = nil
  top_score = -99
  top_decrypt = ""
  (remainder .. 2**32).step(step).each do | putative_key_num |
    putative_key = sprintf("%05x", putative_key_num)[0...5] # Digest::MD5.digest(putative_key_num.to_s(16))[-5..-1]
    # this initializes for decryption
    cipher.decrypt
    cipher.key = putative_key
    putative_plain = cipher.update(cipher_text)
    # score = score_decrypt(putative_plain, plaintext_byte_model)
    score = entropy(putative_plain)
    if score > top_score
        top_key = putative_key
        top_score = score
        top_decrypt = putative_plain
    end

  end
  return [top_key, top_score, top_decrypt]
end

# send/ receive  : push type  send to handle, receive from external 
# yield / take  : pull type - yield to external, take from handle 
pipe = Ractor.new do 
  loop do
      Ractor.yield  Ractor.receive
  end
end

# TODO: how to have all of the loops to stop when one of them returns a score above 0.0
RN = 7
rs = RN.times.map{|i|
  Ractor.new pipe, infile, i, RN do |pipe, infile, i, rn |
    rc4 = OpenSSL::Cipher.new('RC4-40')
    model = [1.1022717747569128, -1.2539935875616006, -1.0715412114558136, 0.38719776947991313, 1.6845307000026097, -0.7395933064620372, -0.8554740185121767, 1.1968470166179053, 0.8013343423198935, -5.039898589649604, -1.7287413912185645, 0.12571441052969412, -0.7597030032711771, 0.8211626750437087, 0.9027128482015736, -1.6177990626724998, -6.749308461295249, 0.1998478612902792, 0.6214967405755889, 1.3658406631655162, -0.546191980118989, -2.6368337320368367, -0.4744424032799319, -6.230841372361, -1.28104218528319, -6.749308461295249].freeze
    cipher_text = File.read(infile)
    # pipe.send(top_answer(step: rn, remainder: i, cipher_text: cipher_text, cipher: rc4, key_byte_size: 5, plaintext_byte_model: model))
    pipe.send(top_answer(step: rn, remainder: i, cipher_text: cipher_text, cipher: rc4, key_byte_size: 5))
  end
}

  RN.times.map{
    pipe.take
}.each {|x| puts "#######\n" + x.join("\t") + "\n\n"}
