#!/bin/bash

#-e DEBUGLOG='true'
docker build -t kres-dnsq-log .
docker run --net=host -v ~/logs:/var/log/whalebone -it kres-dnsq-log