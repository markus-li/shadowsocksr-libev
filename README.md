# shadowsocksR-libev

## Intro

[ShadowsocksR-libev](http://shadowsocks.org) is a lightweight secured SOCKS5
proxy for embedded devices and low-end boxes.

It is a port of [Shadowsocks](https://github.com/shadowsocks/shadowsocks)
created by [@clowwindy](https://github.com/clowwindy), which is maintained by
[@madeye](https://github.com/madeye) and [@linusyang](https://github.com/linusyang).

Current version: 2.5.7 | [Changelog](debian/changelog)


## Features

ShadowsocksR-libev is written in pure C and only depends on
[libev](http://software.schmorp.de/pkg/libev.html) and
[OpenSSL](http://www.openssl.org/) or [mbedTLS](https://tls.mbed.org/) or [PolarSSL](https://polarssl.org/).

In normal usage, the memory footprint is about 600KB and the CPU utilization is
no more than 5% on a low-end router (Buffalo WHR-G300N V2 with a 400MHz MIPS CPU,
32MB memory and 4MB flash).

For a full list of feature comparison between different versions of shadowsocks,
refer to the [Wiki page](https://github.com/shadowsocks/shadowsocks/wiki/Feature-Comparison-across-Different-Versions).

## Notes about this repo
This repo has an updated README for ShadowsocksR, some platforms are not mentioned since they have not been tested, 
therefore, for those platforms, just check the old version of the README.
Since there are no pre-built packages of this version, all references to pre-built binaries have been
 removed from this README.

## Installation

### Distribution-specific guide

- [Debian & Ubuntu](#debian--ubuntu)
    + [Build deb package from source](#build-deb-package-from-source)
    + [Configure and start the service](#configure-and-start-the-service)
- [Fedora & RHEL](#fedora--rhel)
- [OpenSUSE](#opensuse)
    + [Build from source](#build-from-source)
- [Archlinux](#archlinux)
- [NixOS](#nixos)
- [Nix](#nix)
- [Directly build and install on UNIX-like system](#linux)

* * *

### Pre-build configure guide

For a complete list of avaliable configure-time option,
try `configure --help`.

#### Using alternative crypto library

There are three crypto libraries available:

- OpenSSL (**default**)
- mbedTLS
- PolarSSL (Deprecated)

##### mbedTLS
To build against mbedTLS, specify `--with-crypto-library=mbedtls`
and `--with-mbedtls=/path/to/mbedtls` when running `./configure`.

Windows users will need extra work when compiling mbedTLS library,
see [this issue](https://github.com/shadowsocks/shadowsocks-libev/issues/422) for detail info.

##### PolarSSL (Deprecated)

To build against PolarSSL, specify `--with-crypto-library=polarssl`
and `--with-polarssl=/path/to/polarssl` when running `./configure`.

* PolarSSL __1.2.5 or newer__ is required. Currently, PolarSSL does __NOT__ support
CAST5-CFB, DES-CFB, IDEA-CFB, RC2-CFB and SEED-CFB.
* RC4 is only support by PolarSSL __1.3.0 or above__.

#### Using shared library from system

Please specify `--enable-system-shared-lib`. This will replace the bundled
`libev`, `libsodium` and `libudns` with the corresponding libraries installed
in the system during compilation and linking.

### Debian & Ubuntu

#### Install from repository

Shadowsocksr-libev is NOT available in the official repository for Debian 9("Stretch"), unstable, Ubuntu 16.10 and later derivatives.

#### Build deb package from source

Supported Platforms:

* Debian 7 (see below), 8, 9, unstable
* Ubuntu 14.04 (see below), Ubuntu 14.10, 15.04, 15.10 or higher

**Note for Ubuntu 14.04 users**:
Packages built on Ubuntu 14.04 may be used in later Ubuntu versions. However,
packages built on Debian 7/8/9 or Ubuntu 14.10+ **cannot** be installed on
Ubuntu 14.04.

**Note for Debian 7.x users**:
To build packages on Debian 7 (Wheezy), you need to enable `debian-backports`
to install systemd-compatibility packages like `dh-systemd` or `init-system-helpers`.
Please follow the instructions on [Debian Backports](http://backports.debian.org).

This also means that you can only install those built packages on systems that have
`init-system-helpers` installed.

Otherwise, try to build and install directly from source. See the [Linux](#linux)
section below.

``` bash
cd shadowsocksr-libev
sudo apt-get install --no-install-recommends build-essential autoconf libtool libssl-dev \
    gawk debhelper dh-systemd init-system-helpers pkg-config asciidoc xmlto apg libpcre3-dev
automake
dpkg-buildpackage -b -us -uc -i
cd ..
sudo dpkg -i shadowsocksr-libev*.deb
```

#### Configure and start the service

```
# Edit the configuration file
sudo vim /etc/shadowsocksr-libev/config.json

# Edit the default configuration for debian
sudo vim /etc/default/shadowsocksr-libev

# Start the service
sudo /etc/init.d/shadowsocksr-libev start    # for sysvinit, or
sudo systemctl start shadowsocksr-libev      # for systemd
```

### Fedora & RHEL

Supported distributions include
- Fedora 22, 23, 24
- RHEL 6, 7 and derivatives (including CentOS, Scientific Linux)


```
### OpenSUSE

#### Build from source
You should install `zlib-devel` and `libopenssl-devel` first.

```bash
sudo zypper update
sudo zypper install zlib-devel libopenssl-devel
```

Then download the source package and compile.

```bash
git clone https://github.com/markus-li/shadowsocksr-libev.git
cd shadowsocksr-libev
automake
./configure && make
sudo make install
```

### Linux

For Unix-like systems, especially Debian-based systems,
e.g. Ubuntu, Debian or Linux Mint, you can build the binary like this:

```bash
# Debian / Ubuntu
sudo apt-get install --no-install-recommends build-essential autoconf libtool libssl-dev libpcre3-dev asciidoc xmlto
# CentOS / Fedora / RHEL
sudo yum install gcc autoconf libtool automake make zlib-devel openssl-devel asciidoc xmlto
./configure && make
sudo make install
```

#### OpenSSL

```bash
tar zxf openssl-1.0.1e.tar.gz
cd openssl-1.0.1e
./config --prefix="$HOME/prebuilt" --openssldir="$HOME/prebuilt/openssl"
make && make install
```

#### PolarSSL

```bash
tar zxf polarssl-1.3.2-gpl.tgz
cd polarssl-1.3.2
make lib WINDOWS=1
make install DESTDIR="$HOME/prebuilt"
```

Then, build the binary using the commands below, and all `.exe` files
will be built at `$HOME/ss/bin`:

#### OpenSSL

```bash
automake
./configure --prefix="$HOME/ss" --with-openssl="$HOME/prebuilt"
make && make install
```

#### PolarSSL

```bash
automake
./configure --prefix="$HOME/ss" --with-crypto-library=polarssl --with-polarssl=$HOME/prebuilt
make && make install
```

## Usage

For a detailed and complete list of all supported arguments, you may refer to the
man pages of the applications, respectively.

```
    ssr-[local|redir|server|tunnel]

       -s <server_host>           host name or ip address of your remote server

       -p <server_port>           port number of your remote server

       -l <local_port>            port number of your local server

       -k <password>              password of your remote server

       [-m <encrypt_method>]      encrypt method: table, rc4, rc4-md5,
                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,
                                  bf-cfb, camellia-128-cfb, camellia-192-cfb,
                                  camellia-256-cfb, cast5-cfb, des-cfb, idea-cfb,
                                  rc2-cfb, seed-cfb, salsa20 ,chacha20 and
                                  chacha20-ietf

       [-f <pid_file>]            the file path to store pid

       [-t <timeout>]             socket timeout in seconds

       [-c <config_file>]         the path to config file

       [-i <interface>]           network interface to bind,
                                  not available in redir mode

       [-b <local_address>]       local address to bind,
                                  not available in server mode

       [-u]                       enable udprelay mode,
                                  TPROXY is required in redir mode

       [-U]                       enable UDP relay and disable TCP relay,
                                  not available in local mode

       [-A]                       enable onetime authentication

       [-L <addr>:<port>]         specify destination server address and port
                                  for local port forwarding,
                                  only available in tunnel mode

       [-d <addr>]                setup name servers for internal DNS resolver,
                                  only available in server mode

       [--fast-open]              enable TCP fast open,
                                  only available in local and server mode,
                                  with Linux kernel > 3.7.0

       [--acl <acl_file>]         config file of ACL (Access Control List)
                                  only available in local and server mode

       [--manager-address <addr>] UNIX domain socket address
                                  only available in server and manager mode

       [--executable <path>]      path to the executable of ss-server
                                  only available in manager mode

       [-v]                       verbose mode

notes:

    ssr-redir provides a transparent proxy function and only works on the
    Linux platform with iptables.

```

## Advanced usage

The latest shadowsocksr-libev has provided a *redir* mode. You can configure your Linux-based box or router to proxy all TCP traffic transparently.

    # Create new chain
    root@Wrt:~# iptables -t nat -N SHADOWSOCKSR
    root@Wrt:~# iptables -t mangle -N SHADOWSOCKSR

    # Ignore your shadowsocksR server's addresses
    # It's very IMPORTANT, just be careful.
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 123.123.123.123 -j RETURN

    # Ignore LANs and any other addresses you'd like to bypass the proxy
    # See Wikipedia and RFC5735 for full list of reserved networks.
    # See ashi009/bestroutetb for a highly optimized CHN route list.
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 0.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 10.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 127.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 169.254.0.0/16 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 172.16.0.0/12 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 192.168.0.0/16 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 224.0.0.0/4 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -d 240.0.0.0/4 -j RETURN

    # Anything else should be redirected to shadowsocksR's local port
    root@Wrt:~# iptables -t nat -A SHADOWSOCKSR -p tcp -j REDIRECT --to-ports 12345

    # Add any UDP rules
    root@Wrt:~# ip route add local default dev lo table 100
    root@Wrt:~# ip rule add fwmark 1 lookup 100
    root@Wrt:~# iptables -t mangle -A SHADOWSOCKSR -p udp --dport 53 -j TPROXY --on-port 12345 --tproxy-mark 0x01/0x01
    root@Wrt:~# iptables -t mangle -A SHADOWSOCKSR_MARK -p udp --dport 53 -j MARK --set-mark 1

    # Apply the rules
    root@Wrt:~# iptables -t nat -A OUTPUT -p tcp -j SHADOWSOCKSR
    root@Wrt:~# iptables -t mangle -A PREROUTING -j SHADOWSOCKSR
    root@Wrt:~# iptables -t mangle -A OUTPUT -j SHADOWSOCKSR_MARK

    # Start the shadowsocksR-redir
    root@Wrt:~# ss-redir -u -c /etc/config/shadowsocksr.json -f /var/run/shadowsocksr.pid

## ShadowsocksR over KCP

It's quite easy to use shadowsocksR and [KCP](https://github.com/skywind3000/kcp) together with [kcptun](https://github.com/xtaci/kcptun).

The goal of shadowsocksR over KCP is to provide a fully configurable, UDP based protocol to improve poor connections, e.g. a high packet loss 3G network.

### Setup your server

```bash
server_linux_amd64 -l :21 -t 127.0.0.1:443 --crypt none --mtu 1200 --nocomp --mode normal --dscp 46 &
ssr-server -s 0.0.0.0 -p 443 -k passwd -m chacha20 -u
```

### Setup your client

```bash
client_linux_amd64 -l 127.0.0.1:1090 -r <server_ip>:21 --crypt none --mtu 1200 --nocomp --mode normal --dscp 46 &
ssr-local -s 127.0.0.1 -p 1090 -k passwd -m chacha20 -l 1080 -b 0.0.0.0 &
ssr-local -s <server_ip> -p 443 -k passwd -m chacha20 -l 1080 -U -b 0.0.0.0
```

## Security Tips

Although shadowsocksr-libev can handle thousands of concurrent connections nicely, we still recommend
setting up your server's firewall rules to limit connections from each user:

    # Up to 32 connections are enough for normal usage
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKSR_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## License

Copyright (C) 2016 Max Lv <max.c.lv@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
