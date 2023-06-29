

## SSHGuard v0.1
SSH登录动态白名单保护器

**Auth:winger[gnusec]**

ssh登录白名单保护. 使用google动态验证码认证.

SSH login whitelist protection. Utilizes Google Authenticator for dynamic verification.

>使用cfg.ini自定义sccret和通讯加密密钥以及端口等相关配置.

Customize your configuration in cfg.ini with secret, communication encryption key, port, and other related settings.

1: 编译build
Or use a pre-compiled version

Linux|OSX Version:
```
nim c     --passL:-static  --opt:speed  --threads:on -d:releas client.nim
nim c     --passL:-static  --opt:speed  --threads:on -d:releas server.nim
```
Windows Version:

Linux下交叉编译方法
```
sudo apt-get -y install  mingw-w64
nim c   --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc  --passL:-static  --opt:speed  --threads:on -d:releas server.nim

nim c   --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc  --passL:-static  --opt:speed  --threads:on -d:releas  client.nim
```
2: 运行前准备好系统环境
Prepare the system environment before running.
```
echo "">/etc/hosts.allow
echo "sshd: ALL">/etc/hosts.deny
```

3: 修改配置文件
Modify the configuration file.

在修改好cfg.ini配置文件(secret和ip参数必须修改)之后, 分别在服务器端和客户端运行程序.
After modifying the cfg.ini configuration file (ensure to modify the 'secret' and 'ip' parameters), run the program separately on the server-side and client-side.

in cfg.ini file
secret为你的独有密码
io参数为ssh服务器的公网IP,这个参数是给client使用的,服务器端用不到,服务器端默认监控所有接口.The 'secret' is your unique password. The 'ip' parameter is the public IP address of the SSH server. This parameter is used by the client and is not required on the server-side. By default, the server-side monitors all interfaces.

4: 运行
execute

Start the server-side first.

```
./server
```


Then run the client-side.

```
client.exe
```

**Community discussion group**
Discord:
https://discord.gg/3WnegcP5TK
WX:
GNUSEC
**License**

SSHGuard is under the GPL-3.0 license. See the LICENSE file for details.