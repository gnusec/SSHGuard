# SSHGuard v0.1

SSHGuard是SSH登录的动态白名单保护器，它使用Google Authenticator进行动态验证。

SSHGuard is a dynamic whitelist protector for SSH logins. It utilizes Google Authenticator for dynamic verification.

## 作者 Author
winger[gnusec]

## 特性 Features
- SSH登录白名单保护
- 使用Google Authenticator进行动态验证
- 可自定义配置

- SSH login whitelist protection
- Google Authenticator for dynamic verification
- Customizable configuration

## 配置 Configuration
你可以在`cfg.ini`中自定义你的配置，包括secret、通讯加密密钥、端口等相关设置。

You can customize your configuration in `cfg.ini` with secret, communication encryption key, port, and other related settings.

## 开始使用 Getting Started

### 1. 构建 Build
你可以编译源代码，或者使用预编译的版本。

You can either compile the source code or use a pre-compiled version.

#### Linux|OSX版本 Version:

```bash
nim c --passL:-static --opt:speed --threads:on -d:release client.nim
nim c --passL:-static --opt:speed --threads:on -d:release server.nim
```

#### Windows版本 Version:

Linux下的交叉编译方法：

Cross-compilation method for Linux

```bash
sudo apt-get -y install mingw-w64
nim c --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc --passL:-static --opt:speed --threads:on -d:release server.nim
nim c --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc --passL:-static --opt:speed --threads:on -d:release client.nim
```

### 2. 准备系统环境 Prepare the System Environment

运行前，准备好系统环境：

Before running, prepare the system environment:
```
echo "">/etc/hosts.allow
echo "sshd: ALL">/etc/hosts.deny
```
### 3. 修改配置文件 Modify the Configuration File

在修改好cfg.ini配置文件（确保修改'secret'和'ip'参数）之后，分别在服务器端和客户端运行程序。

After modifying the cfg.ini configuration file (ensure to modify the 'secret' and 'ip' parameters), run the program separately on the server-side and client-side.

在cfg.ini文件中：
>'secret'是你的独有密码

>'ip'是SSH服务器的公网IP，这个参数是给client使用的，服务器端用不到，服务器端默认监控所有接口。

In cfg.ini file:
>'secret' is your unique password

>'ip' is the public IP address of the SSH server. This parameter is used by the client and is not required on the server-side. By default, the server-side monitors all interfaces.

### 4. 执行 Execution
首先启动服务器端：

Start the server-side first:

```
./server
```

然后运行客户端：

Then run the client-side:

```
client
```

## 社区讨论组 Community Discussion Group
Discord: 

>https://discord.gg/3WnegcP5TK

微信 WeChat

>GNUSEC



## 许可证 License

SSHGuard使用GPL-3.0许可证，详情请查看LICENSE文件。

SSHGuard is under the GPL-3.0 license. See the LICENSE file for details.
