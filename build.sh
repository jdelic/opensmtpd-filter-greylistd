#!/bin/bash
go get
go build

fpm \
    -s dir \
    -t deb \
    -p opensmtpd-filter-greylistd_0.6.1.deb \
    -n opensmtpd-filter-greylistd \
    -v "0.6.1-0" \
    -m "Jonas Maurus" \
    -d "opensmtpd (>=6.8.0)" \
    -d "opensmtpd (<<7.5)" \
    -d "greylistd" \
    --description "Provides integration with greylistd for OpenSMTPD." \
    --url "https://github.com/jdelic/opensmtpd-filter-greylistd" \
    opensmtpd-filter-greylistd=/usr/lib/x86_64-linux-gnu/opensmtpd/filter-greylistd
