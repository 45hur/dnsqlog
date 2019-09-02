#!/bin/bash

docker build -t kres-dnsq-log .
docker run --net=host -v ~/logs:/var/log/whalebone -e DEBUGLOG='true' -it kres-dnsq-log