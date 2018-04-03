# JwtSessionBundle

JwtSessionBundle is a PHP session replacement. Instead of use FileSystem, just use Json Web Token

## Motivation
The default PHP Session does not work in different servers using round robin or other algorithms. This occurs because PHP Session are saved by default in the file system.

There are implementations can save the session to REDIS or MEMCACHED, for example. But this requires to you create a new server to store this session and creates a single point of failure. To avoid this you have to create REDIS/MEMCACHED clusters.

But if you save the session into JWT Token you do not need to create a new server. Just to use.

## Security information
The JWT Token cannot be changed, but it can be read. This implementation save the JWT into a client cookie.
Because of this do not store in the JWT Token sensible data like passwords.

## Installation
