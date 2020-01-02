Golang implementation of a Greylist filter for OpenSMTPD
========================================================

This is a simple implementation based off my
`opensmtpd-filters-go <osfgo_>`__ library.

Debian ships with ``greylistd``, a simple greylist management server written in
Python. ``greylistd`` implements a simple protocol over a local socket that 
manages the greylisting of IP addresses, HELO hostnames and RCPT addresses. 
This filter currently only uses the sender's host's IP address.


How to use this
---------------

Once the packages are uploaded, you will be able to install on Debian Buster 
like this:

::

    echo "deb http://repo.maurus.net/buster/opensmtpd/ mn-opensmtpd main" > /etc/apt/sources.list.d/opensmtpd-greylistd.list
    apt-get update
    apt-get install greylistd opensmtpd-filter-greylistd


Example usage in smtpd.conf
---------------------------

In your OpenSMTPD configuration activate ``filter-greylistd``:

::

    filter "greylistd" proc-exec "/usr/lib/x86_64-linux-gnu/opensmtpd/filter-greylistd"
    listen on "127.0.0.1" port 25 filter greylistd


.. _osfgo: https://github.com/jdelic/opensmtpd-filters-go
