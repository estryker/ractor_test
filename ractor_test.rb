#!/usr/bin/env ruby

def compute(i)
  sleep 5
  return i
end

pipe = Ractor.new do
    loop do
      Ractor.yield Ractor.receive
    end
  end

  RN = 7
  rs = RN.times.map{|i|
    Ractor.new pipe, i do |pipe, i|
      pipe << compute(i)
    end
  }

  RN.times.map{
    pipe.take
}.each {|x| puts x}
