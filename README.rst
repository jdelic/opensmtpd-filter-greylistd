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

On Debian 13 (Trixie), both ``opensmtpd`` and ``greylistd`` are available directly
from the main archive, so first install the prerequisites:

::

    apt-get update
    apt-get install -y opensmtpd
    apt-get install --no-install-recommends -y greylistd  # note the warning this gives about adapting permissions for your local MTA

Second, **either** install from the packages created here (note this repository
currently only publishes Buster packages, but they still work on Trixie since
this project has no Buster-specific dependencies):

::

    echo "deb http://repo.maurus.net/buster/opensmtpd/ mn-opensmtpd main" > /etc/apt/sources.list.d/opensmtpd-greylistd.list
    apt-get update
    apt-get install opensmtpd-filter-greylistd
    install /usr/lib/x86_64-linux-gnu/opensmtpd/filter-greylistd /usr/libexec/opensmtpd/filter-greylistd

**or** install from source:

::

    sudo apt-get install --no-install-recommends golang
    go install github.com/jdelic/opensmtpd-filter-greylistd@latest
    sudo install ~/go/bin/opensmtpd-filter-greylistd /usr/libexec/opensmtpd/filter-greylistd


Third, adapt the permissions, because greylistd only comes pre-configured to work with exim:

::

    # run greylistd as opensmtpd, because opensmtpd doesn't call initgroups() on filter subprocesses
    chown -R opensmtpd:opensmtpd /var/lib/greylistd/ /var/run/greylistd/
    sed -i 's/^user=.*$/user=opensmtpd/' /etc/init.d/greylistd
    sed -i 's/^group=.*$/group=opensmtpd/' /etc/init.d/greylistd
    systemctl daemon-reload && systemctl restart greylistd


Example usage in smtpd.conf
---------------------------

In your OpenSMTPD configuration activate ``filter-greylistd``:

::

    filter "greylistd" proc-exec "filter-greylistd"
    listen on "127.0.0.1" port 25 filter greylistd


.. _osfgo: https://github.com/jdelic/opensmtpd-filters-go
