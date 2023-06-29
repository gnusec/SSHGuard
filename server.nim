# 客户端测试方法
# 每隔5秒发送一次token
# while true; do echo "your_secret_token" | nc 127.0.0.1 12345; sleep 5; done
# @todo
# 1. 加入字符串加密
# https://github.com/itaymigdal/NimProtect 




import net, os, times, strutils, strformat, asyncdispatch, asyncnet
import sequtils
import tables
import sets
import parsecfg
import auth


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
SSHGuard server v0.1
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

const
  FILE_HOSTS_ALLOW = "/etc/hosts.allow"
  TOKEN_MAXLEN = 108 # token cannot be longer than this
  # token = "your_secret_token" # 你的认证token
  # HEARTBEAT_EXPIRED = initDuration(minutes = 10)        # 心跳过期时间, 10分钟没心跳就删除白名单
  # @todo
  # 心跳和超时时间放配置文件里头
  # HEARTBEAT_EXPIRED = initDuration(seconds = 10)        # 心跳过期时间, 10秒没心跳就删除白名单
  # heartbeat = 5.minutes       # 心跳间隔
  # HEARTBEAT_INTERVAL = initDuration(minutes = 1)       # 白名单文件更新间隔，这个时间间隔越短越好
  # HEARTBEAT_INTERVAL = initDuration(seconds = 5)       # 白名单文件更新间隔，这个时间间隔越短越好

# 以后可以做一个在编译期,把配置文件信息读取进来,编入二进制文件.
let CFG = loadConfig("./cfg.ini")
# echo CFG
let SECRET = CFG.getSectionValue("credentials", "secret")
let COMMUNICATION_KEY = CFG.getSectionValue("credentials", "communicationKey")
let COMMUNICATION_IV = CFG.getSectionValue("credentials", "communicationIV")
let HEARTBEAT_EXPIRED = initDuration(seconds = parseInt(CFG.getSectionValue("server","heartbeatExpired")))
let HEARTBEAT_INTERVAL = initDuration(seconds = parseInt(CFG.getSectionValue("server","heartbeatInterval")))

let SERVERADDR = CFG.getSectionValue("server","server")
let SERVERPORT = parseInt(CFG.getSectionValue("server","port"))

var AUTH = newAuth(SECRET,COMMUNICATION_KEY,COMMUNICATION_IV)

type
  IPAddress = string
  LastHeartbeat = Time
  IPTable* = object
    table*: Table[IPAddress, LastHeartbeat]


var IPTableWhite = initHashSet[IPAddress]()
proc initIPTable*(): IPTable =
  return IPTable(table: initTable[IPAddress, LastHeartbeat]())

proc addIP*(self: var IPTable, ip: IPAddress, time: LastHeartbeat) =
  self.table[ip] = time

proc delIP*(self: var IPTable, ip: IPAddress) =
  self.table.del(ip)

proc checkIP*(self: IPTable, ip: IPAddress): bool =
  return ip in self.table

var clientIpTable = initIPTable()


# clientIpTable.addIP("1.1.1.1",getTime())
# var Client = initTable[IPAddress, LastHeartbeat]()
# var clients = initTable[IPAddress, LastHeartbeat]()

# proc addIP(ip: IPAddress, time: LastHeartbeat) =
#   clients[ip] = time

# proc checkIP(ip: IPAddress): bool =
#   return ip in clients

# type
#   Client = ref object
#     ip: string
#     LastHeartbeat: Time

# var clients: seq[Client]

proc handleClient(client: AsyncSocket) {.async.} =
  # echo "Beging handleClient"
  let (client_ip,_) = client.getPeerAddr()
  let msg = await client.recv(size = TOKEN_MAXLEN)
  # let msg = await client.recv(TOKEN_MAXLEN)
  # let msg = await client.recv(TOKEN_MAXLEN)
  # echo "client msg=>",msg
  # echo AUTH.decryptNetworkPackets(msg)
  # echo "-------------------------"
  # echo "token=>",repr(SECRET)

  # 关闭客户连接,防止服务器连接过都
  client.close
  # 
  # echo AUTH.check(AUTH.decryptNetworkPackets(msg))
  if AUTH.check(AUTH.decryptNetworkPackets(msg)):
    # echo fmt"Adding {client_ip} to ./allow"
    # @todo
    # 这个文件的路径也写道配置文件里头
    if not IPTableWhite.contains(client_ip):
      echo fmt("Adding {client_ip} to /etc/hosts.allow")
      let dfile = open(FILE_HOSTS_ALLOW, fmAppend)
      defer:
        dfile.close()
      write(dfile,fmt("sshd:{client_ip}:allow\n"))
      # writeFile(FILE_HOSTS_ALLOW, fmt"sshd:{client_ip}:allow", fmAppend)

    clientIpTable.addIP(ip = client_ip, time = getTime())
    IPTableWhite.incl(client_ip)
    # @todo
    # 后面增加 一些频率监控和黑名单机制(爆破的情况)
  #   if clientIpTable.checkIP(client_ip):
      
  #     echo "client.isClosed=>",client.isClosed
  #     # clients.add Client(ip: client_ip, LastHeartbeat: getTime())
  #     clientIpTable.addIP(ip = client_ip, time = getTime())
  #   else:
  #     # 如果存在ip，即更新最后的心跳时间
  #     clientIpTable.table[client_ip] = getTime()
  else:
    # @todo
    # 黑名单机制和日志记录
    discard
    # echo "client.isClosed=>",client.isClosed
    # echo fmt("Invalid token from {client_ip}")

proc listen() {.async.} =
  let server = newAsyncSocket()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(SERVERPORT))
  server.listen()

  while true:
    let client = await server.accept()
    # echo "new client =>",repr(client)
    asyncCheck handleClient(client)

proc checkHeartbeats() {.async.} =
  while true:
    echo "Beging checkHeartbeats"
    var tmpSeq = newSeq[IPAddress]()
    for (clientIp,clientIp_lastHeartbeat_time) in clientIpTable.table.pairs:
      if getTime() - clientIp_lastHeartbeat_time > HEARTBEAT_EXPIRED:
        echo "客户端心跳超时"
        # echo clientIp , clientIp_lastHeartbeat_time
        # echo "HEARTBEAT_EXPIRED=>" , HEARTBEAT_EXPIRED

        # echo fmt"Removing {clientIp} from ./allow"
        # 下面自动化的把每行的换行给删除了
        let lines = readFile(FILE_HOSTS_ALLOW).splitLines()
        echo repr(lines)
        let newLines = lines.filterIt(it != fmt("sshd:{clientIp}:allow"))
        # echo "newLines=>",newLines
        writeFile(FILE_HOSTS_ALLOW, newLines.join("\n"))
        # 从客户端ip地址表中删除指定的客户端ip
        # var x = getTime()
        # discard clientIpTable.table.pop(clientIp, x)
        # @todo
        # Nim无法在迭代的过程中删除元素
        # 所以下面的写法是错误的
        # clientIpTable.delIP(clientIp)
        tmpSeq.add(clientIp)
        # echo "Now clientIpTable.table->",clientIpTable.table

    for clientIp in tmpSeq:
      # 这里删除客户端ip还是需要锁下clientIpTable的
      # @todo
      clientIpTable.delIP(clientIp)
    
    # echo "Beging sleepAsync"
    await sleepAsync(int(HEARTBEAT_INTERVAL.inMilliseconds))

asyncCheck listen()
asyncCheck checkHeartbeats()
runForever()