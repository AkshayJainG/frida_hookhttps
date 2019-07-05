# hookhttps
use frida auto hook https for androind
这个脚本的主要功能是，hook了客户端要验证服务器证书的地方，让客户端永远认为服务器的证书是对的。
使用这个脚本以后，就可以用替换证书的方法，抓取https的包了


## 
1. root phone
2. install frida_server to phone
- adb forward tcp:27042 tcp:27042
- adb forward tcp:27043 tcp:27043
3. run script

## usages
frida -U -f "package" -l frida_http_hook.js --no-pause
