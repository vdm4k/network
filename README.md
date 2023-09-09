# Network
Network is a easy scalable labrary for simplifying working with socket API (non blocking/blocking mode).
TCP, SCTP, SSL + TCP, SSL + SCTP, DTLS

## ***Why?***
1. Small labrary. It's easy to write write server/client applications based on it. By default it is using non blocking sockets
2. It has universal interface for many streaming protocols ( tcp (+ ssl), sctp (+ ssl), dtls )
3. Doesn't use exceptions. To handle errors you can set your callback function *stream->set_state_changed_cb(cb_function)* and check when a socket will become inactive *!stream->is_active()*. we can get error description *stream->get_error_description()*
4. It has minimal dependecies. 
5. Easy to test application. You need only to implement stream interface and check what data your application send.
6. It's easy to change socket type hence it's easy to move from tcp to ssl+tcp and vice versa
7. If socket fails we can easily recreate it *failed_stream = manager.create_stream(failed_stream->get_settings());* Hence we can have pool of streams and recreate if some of them fails.


## ***Build***

You need cmake

1. mkdir build
2. cd build
3. cmake ../
   1. cmake build options (by default build only plain TCP/UDP support)
      1. with TCP SSL support *-DWITH_TCP_SSL=ON* 
      2. with UDP SSL support *-DWITH_UDP_SSL=ON* 
      3. with SCTP support *-DWITH_SCTP=ON*
      4. with SCTP SSL support *-DWITH_SCTP_SSL=ON*
      5. buid examples *-DWITH_EXAMPLES=ON*
      6. use custom open ssl build (actual for SCTP + SSL and dtls) *-DOPENSSL_DIR=/path/to/build/my-openssl*
      7. use sanitizer *-DWITH_SANITIZER=ON*
      8. build all *cmake -DWITH_SANITIZER=ON -DWITH_SCTP=ON -DWITH_SCTP_SSL=ON -DWITH_TCP_SSL=ON -DOPENSSL_DIR=/path/to/build/my-openssl -DWITH_EXAMPLES=ON -DWITH_UDP_SSL=ON ../*
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

## UDP

### Client

Simple client with non blocking sockets. Oriented only on one connection hence we need to set bind ip/port

## SSL + UDP

### Server

Server works as expected. No special preconditions. By default using non blocking mode. Using openSSL for secure connections

### Client

Client works as expected. No special preconditions. By default using non blocking mode. Using openSSL for secure connections

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

There are many problems with SCTP implementation in openSSL

1. First off all it is disabled by default. Hence you need to download it and build with SCTP support
You can do it like this 
***git clone git://git.openssl.org/openssl.git
./config sctp --prefix=$HOME/my-openssl/ && make -j8 && make -j8 install***
2. Enable support in linux ***sudo sysctl -w net.sctp.auth_enable=1***
3. It is slow (maybe need to discove why) ~50 messages per second
4. Actual version of openSSL consist bug (https://github.com/openssl/openssl/issues/20643)

