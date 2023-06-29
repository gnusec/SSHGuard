# nimble install pixie qrgen base32 otp

import otp,os
import base32
import QRgen
import QRgen/renderer
import pkg/pixie
import strutils
import nimAES
import strutils


var debug = false



type
    Auth = ref object of RootObj
        secret: string # 关键校验基准key,用于生成Google动态key
        # 下面的aes cbc 加密key是,只能是16、24、32字节。如果密码字符串长度不够，
        # 可以在字符串末尾追加一些特定的字符，或者重复密码字符串，直到满足最少的长度
        communicationKey: string # 网络流量对称解密key
        communicationIV: string # AES 的 IV
        # interval: int # 检测频率
        # whiteips: seq[(string,int)] # 白名单
        # blackips: seq[(string,int)] # 黑名单

# proc at*(self: HOTP, count: int): int =
#   return self.generate(count)


proc adjustAesCbcEncryptionKey(key: string): string =
  const desiredLengths = @[16, 24, 32]
  let keyLength = key.len

  if keyLength > desiredLengths[2]:
    result = key[0 ..< desiredLengths[2]]
  else:
    for desiredLength in desiredLengths:
      if keyLength <= desiredLength:
        result = key & " ".repeat(desiredLength - keyLength)
        break

  return result

# padding 字符串长度到指定长度的倍数,
proc padStringToMultiple(str: string, desiredLength: int = 16, paddingChar: char = ' '): string =
  var strLength = len(str)
  var paddingLength = desiredLength - (strLength mod desiredLength)
  return str & paddingChar.repeat(paddingLength)

# padding 字符串长度到指定长度的倍数,这里默认16的倍数
proc adjustAesCbcInput(text: string): string =
  return padStringToMultiple(text)

#CBC的IV必须是16字节
proc adjustAesCbcIV(iv: string): string =
  return padStringToMultiple(iv)[0..15]


# 初始化
# 默认每30秒检测一次白名单，超过10min未心跳的ip加入黑名单(后期复杂了,再加黑白名单)
# proc newAuth*(secret: string , interval: int = 30 , whiteips:seq[(string,int)] = @[] , blackips:seq[(string,int)] = @[]) : Auth =
proc newAuth*(secret: string,communicationKey: string , communicationIV: string) : Auth =
    new(result)
    result.secret = secret
    # 
    result.communicationKey = adjustAesCbcEncryptionKey(communicationKey)
    result.communicationIV = adjustAesCbcIV(communicationIV)
    # echo "[newAuth] result->",result.communicationKey.len
    # echo repr(result)
    return result
    # result.interval = interval
    # result.whiteips = whiteips
    # result.blackips = blackips


# 
# Google动态认证码生成
proc gen*(self: Auth): string =
    return intToStr(newTotp(encode(self.secret)).now(),6) 



# 当前使用的方法
# 六位数的google动态认证码比对
proc check*(self: Auth , client_token:string): bool =
    # echo "Beging Auth.check->",repr(intToStr(newTotp(encode(self.secret)).now(),6))
    # echo "client_token->",repr(client_token)
    # 因为encryptCBC的加密内容必须是16字节的倍数,所以客户端生成的6位Google动态码,padding10位的空格
    # aes解密回来的client_token必须删除结尾的空格
    return intToStr(newTotp(encode(self.secret)).now(),6)  ==  client_token.strip()


# 加密网络加密包
# 这里用aes来做网络传输数据的加密
proc encryptNetworkPackets*(self: Auth, packets: string ): string =
    var aes = initAES()
    try:
        # echo "Befor setEncodeKey=>[",self.communicationKey,"]",self.communicationKey.len,"-",self.secret.len
        if aes.setEncodeKey(self.communicationKey):
            # echo "[encryptNetworkPackets]=>",aes.encryptCBC("abcd"),"<="
            # echo "self.communicationIV=>",self.communicationIV
            # encryptCBC will change communicationIV. so must use a  tmp copy
            var tmpIV = self.communicationIV
            result = aes.encryptCBC(tmpIV, adjustAesCbcInput(packets))
            # echo "self.communicationIV=>",self.communicationIV
            # echo "result->",result
            # echo "packets->",packets
    except:
        echo getCurrentExceptionMsg()
        discard


# 解密网络加密包
# 这里用aes来做网络传输数据的加解密
proc decryptNetworkPackets*(self: Auth, packets: string ): string =
    var aes = initAES()
    try:
        if aes.setDecodeKey(self.communicationKey):
            # echo "self.communicationKey=>",self.communicationKey
            # echo "self.communicationIV=>",self.communicationIV
            var tmpIV = self.communicationIV
            result = aes.decryptCBC(tmpIV, packets)
            # echo "self.communicationIV=>",self.communicationIV

    except:
        discard
    # return result
# test demo
# var t = newAuth("shithacking")
# echo "Checking resutl:=> ", t.check("632623")
# echo t.whiteips.len
# echo t.blackips.len

# debug = true
if debug:
    #let totp = newTotp("abcdefgabcdefghijk123")

    let totp = newTotp(encode("shithacking"))
    # let totp = newTotp(encode("12323abcds"))

    #echo totp.provisioning_uri()


    echo totp.provisioning_uri("a@zzz.com")

    echo totp.provisioning_uri("a@zzz.com")


    let myQR = newQR(totp.provisioning_uri("a@zzz.com"))
    myQR.printTerminal

    let myQRImg = myQR.renderImg("#1d2021","#98971a",100,100,25)
    writeFile( myQRImg  , "t1.png")


    echo  intToStr(totp.now(),6)



    sleep(5000)

    echo  intToStr(totp.now(),6)


    sleep(5000)

    echo  intToStr(totp.now(),6)


    sleep(5000)

    echo  totp.now()


    sleep(5000)

    echo  intToStr(totp.now(),6)


    sleep(5000)

    echo  intToStr(totp.now(),6)


    sleep(5000)

    echo  intToStr(totp.now(),6)


    sleep(5000)

    echo  intToStr(totp.now(),6)
