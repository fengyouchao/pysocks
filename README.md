# PySocks
**PySocks** is a simple SOCKS5 server without any third-party dependencies. 

## Progress

* CONNECT commnad - OK
* UDP ASSOCIATE - NO
* BIND - NO
* No Authentication Required - YES
* USERNAME/PASSWORD Authentication - YES
* GSS-API - NO

## Environment
Python 3.6

> If you need to use it in a python2 environment, you can roll back to 61edb32. I will consider compatibility with python2 in the future.

## Install


```
    $ git clone https://github.com/fengyouchao/pysocks.git ~/pysocks
```

## Usage

```
$ python ~/pysocks/socks5.py start  # Start a socks5 server
$ python ~/pysocks/socks5.py status # Print socks5 server status
$ python ~/pysocks/socks5.py stop  # Stop socks5 server
$ python ~/pysocks/socks5.py start --auth root:1235 admin:1234 # Only allow clients that provide the specified username and password
$ python ~/pysocks/socks5.py start --allow-ip 10.0.0.5 10.0.0.6 # Only allow clients from 10.0.05 or 10.0.06
$ python ~/pysocks/socks5.py -h # print help information
$ python ~/pysocks/socks5.py start -h # print help information for start subcommand
$ python ~/pysocks/socks5.py status -h # print help information for status subcommand
$ python ~/pysocks/socks5.py stop -h # print help information for stop subcommand
```

## Thanks

I wrote **PySocks** after a week of learning python, so there is a lot of immature code in it. After completing this project, I haven't updated it for a long time. I am very grateful to the friends who submitted PR to this project during this period.

Thanks to [C W](https://github.com/fake-name) for migrating **PySocks** to python3.

