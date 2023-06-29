# 客户端定时向服务端发送认证凭证

import asyncdispatch, asyncnet, times , strutils
import auth
# import base64
import parsecfg
import os

# const
#     token = "your_secret_token" # 你的认证token
#     heartbeat = initDuration(seconds = 5)# 心跳间隔
#     serverAddr =  "127.0.0.1"
#     # connected

#     # HEARTBEAT_EXPIRED = initDuration(seconds = 10)        # 心跳过期时间, 10分钟没心跳就删除白名单

# 以后可以做一个在编译期,把配置文件信息读取进来,编入二进制文件.

const sshGuardLogo = """
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄  
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ 
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
▐░▌          ▐░▌          ▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░▌ ▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌▐░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
 ▀▀▀▀▀▀▀▀▀█░▌ ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌ ▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀█░█▀▀ ▐░▌       ▐░▌
          ▐░▌          ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌     ▐░▌  ▐░▌       ▐░▌
 ▄▄▄▄▄▄▄▄▄█░▌ ▄▄▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌      ▐░▌ ▐░█▄▄▄▄▄▄▄█░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░▌ 
 ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀  
"""

const usage = """
SSHGuard client v0.1
Auth: winger[gnusec]

ssh登录白名单保护. 使用google动态验证码认证.
SSH login whitelist protection. Utilizes Google Authenticator for dynamic verification.

使用cfg.ini自定义sccret和通讯加密密钥以及端口等相关配置.
Customize your configuration in cfg.ini with secret, communication encryption key, port, and other related settings.
"""

echo sshGuardLogo


# Print usage message with line breaks
for line in usage.splitLines:
    echo line



let CFG = loadConfig("./cfg.ini")
# echo CFG
let SECRET = CFG.getSectionValue("credentials", "secret")
let COMMUNICATION_KEY = CFG.getSectionValue("credentials", "communicationKey")
let COMMUNICATION_IV = CFG.getSectionValue("credentials", "communicationIV")
var AES = newAuth(SECRET,COMMUNICATION_KEY,COMMUNICATION_IV)

# echo CFG
let SERVERADDR = CFG.getSectionValue("server","ip")
# echo SERVERADDR
# echo "CFG.getSectionValue(\"server\",\"port\")[",CFG.getSectionValue("server","port"),"]"
let SERVERPORT = parseInt(CFG.getSectionValue("server","port"))
# @todo
# 是服务器的超期时间的一般, 心跳后期可以做成一个随机范围防止gfw抖动
let HEARTBEAT_EXPIRED = initDuration(seconds = parseInt(CFG.getSectionValue("server","heartbeatExpired")) div 2)
# echo HEARTBEAT_EXPIRED
let HEARTBEAT_INTERVAL = initDuration(seconds = parseInt(CFG.getSectionValue("server","heartbeatInterval")))
# echo HEARTBEAT_INTERVAL
# echo "SERVERPORT->",SERVERPORT


proc sendHeartbeat() {.async.} =
  let client = newAsyncSocket()
  echo("Connecting to ", SERVERADDR)
  await client.connect(SERVERADDR, Port(SERVERPORT))
  echo("Connected!")

  var googleCode = AES.gen()
  echo "googleCode->",googleCode
  # var aes_content = AES.encryptNetworkPackets(googleCode)
  # echo "aes_content->[", aes_content ,"]"
  # var base64_content = base64.encode(AES.encryptNetworkPackets(googleCode))
  # echo "base64_content->[", base64_content ,"]"
  waitFor       client.send(AES.encryptNetworkPackets(googleCode))
  # waitFor       client.send(base64_content)
  # sleep(1000)
  client.close

proc main() {.async.} =
  while true:
    asyncCheck sendHeartbeat()
    # echo "time->",heartbeat.inSeconds, "-->" , heartbeat
    # echo heartbeat.inMilliseconds
    # echo repr(heartbeat)
    await sleepAsync(int(HEARTBEAT_EXPIRED.inMilliseconds))

waitFor main()
runForever()
