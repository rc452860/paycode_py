#/usr/bin/env python
# -*- coding:utf-8 -*-
from hashlib import sha1
import hmac
import base64
import time
import logging

current_milli_time = lambda :int(round(time.time() *1000))
bytes_to_hex_string = lambda arr:' '.join('{:02x}'.format(ord(c)) for c in arr)

class Paycode(object):
    def __init__(self,key,flag):
        self.key = key
        self.flag = flag
    
    def next(self,uid,clock):
        time  = int(current_milli_time() / (1000*clock))
        hash_array = self.hmacsha1(str(time))
        offset = ord(hash_array[19])&0xf
        sub_hash_array = hash_array[offset:offset+4]
#         print bytes_to_hex_string(hash_array)
#         print '{0}:{1}'.format(offset,offset+4)
#         print bytes_to_hex_string(sub_hash_array)
        result = 0
        result = (ord(sub_hash_array[0])&0x7F)<<24
        result += (ord(sub_hash_array[1])&0xFF)<<16
        result += (ord(sub_hash_array[2])&0xFF)<<8
        result += (ord(sub_hash_array[3])&0xFF)
        result = result % pow(10,4)
        return self.generator_otp(result,uid)
    
    def generator_otp(self,result,uid):
        # uid向前推进10000000000为了避免出现uid太短情况生成的otp令牌出现大量一样的情况
        uid += 10000000000
        min_result = pow(10,3)
        while(result < min_result):
            result *= 10
        factor = 5
        x = result
        y = int(uid/x+factor*x)
        z = uid % x
        return self.opt_format(x,y,z)
    
    def opt_format(self,x,y,z):
        return '{}{:0<4}{:0<8}{:0<4}'.format(self.flag,x,y,z)
    
    def hmacsha1(self,message):
        hash = hmac.new(self.key,message,sha1).digest()
        return bytes(hash)

if __name__ == '__main__':
    paycode = Paycode('killer',36)
    while(True):
        print paycode.next(70,1)
        time.sleep(1)