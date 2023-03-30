# Network
Network is a easy scalable labrary for simplifying working with socket API (non blocking/blocking mode).
TCP, SCTP, SSL + TCP, SSL + SCTP, DTLS

## ***Why?***
1. I want small proxy labrary to write server/client fast enought. By default it is using non blocking sockets
2. Library doesn't use exceptions. To handle errors you can send your callback function *stream->set_state_changed_cb(cb_function)*
3. It has minimal dependecies. 
4. Easy to test apps. You need only to implement stream interface and check what message your application send.
5. It is easy to change socket type - you need only send specific struct settings. Hence it is easy to move from tcp to ssl+tcp
6. If socket fails we can easy recreate it *failed_stream = manager.create_stream(failed_stream->get_settings());* Hence we can have pool of stream and recreate if some of them failed.


## ***Build***

You need cmake

1. mkdir build
2. cd build
3. cmake ../
   1. cmake build options (by default build only with TCP support)
      1. with SSL support *-DWITH_SSL=ON*
      2. with SCTP support *-DWITH_SCTP=ON*
      3. with SSL support (only for tcp) *-DWITH_SSL=ON*
      4. buid apps (examples) *-DWITH_APP=ON*
      5. custom open ssl build (actual for SCTP + SSL and dtls) *-DOPENSSL_DIR=/path/to/build/my-openssl*
      6. use sanitizer *-DWITH_SANITIZER=ON*
      7. build all *cmake -DWITH_SANITIZER=ON -DWITH_SCTP=ON -DWITH_SCTP_SSL=ON -DWITH_SSL=ON -DOPENSSL_DIR=/home/vdm4k/libs/my-openssl -DWITH_APP=ON ../*
4. make 

## TCP

### Server

Simple server with non blocking sockets. No special preconditions.

### Client

Simple client with non blocking sockets. No special preconditions.

## SSL + TCP

### Server

Server works as expected. No special preconditions. By default using non blocking mode. Using openSSL for secure connections

### Client

Client works as expected. No special preconditions. By default using non blocking mode.Using openSSL for secure connections

## SCTP

You need to install libsctp - ***sudo apt-get install libsctp-dev***

### Server

Server works as expected. No special preconditions. By default using non blocking mode. Using openSSL for secure connections

### Client

Client works as expected. No special preconditions. By default using non blocking mode.Using openSSL for secure connections

## SSL + SCTP

### Server

Server works good, but not so fast as I expected.

### Client

Unfortunately openssl is ready only for blocking mode.

#### Problems

There are some problems with openSSL implementation for SCTP

1. First off all it is disabled by default. Hence you need to download it and build with SCTP support
You can do it like this 
***git clone git://git.openssl.org/openssl.git
./config sctp --prefix=$HOME/my-openssl/ && make -j8 && make -j8 install***
2. Enable support in linux ***sudo sysctl -w net.sctp.auth_enable=1***

