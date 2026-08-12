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
from the main archive, so first install the prerequisites. ``--no-install-recommends``
is important as apt may remove opensmtpd and install exim
because of greylistd's package dependencies (see `Debian Bug 992064 <bug992064_>`__):

::

    apt-get update
    apt-get install -y opensmtpd
    apt-get install --no-install-recommends -y greylistd  # note the warning this gives about adapting permissions for your local MTA

Second, install ``filter-greylistd`` itself, **either** from a pre-built package
**or** by building it from source yourself.

Installing the package
~~~~~~~~~~~~~~~~~~~~~~~

``opensmtpd-filter-greylistd`` is published as a Debian package for Trixie at
repo.maurus.net:

::

    curl -o /etc/apt/keyrings/maurusnet-package-archive.gpg http://repo.maurus.net/02CBD940A78049AF.pem
    echo "deb [signed-by=/etc/apt/keyrings/maurusnet-package-archive.gpg arch=amd64] http://repo.maurus.net/release/trixie mn-release main" > /etc/apt/sources.list.d/opensmtpd-greylistd.list
    apt-get update
    apt-get install opensmtpd-filter-greylistd

Building from source
~~~~~~~~~~~~~~~~~~~~~

Alternatively, build and install ``filter-greylistd`` yourself using ``go build``:

::

    sudo apt-get install --no-install-recommends golang
    git clone https://github.com/jdelic/opensmtpd-filter-greylistd.git
    cd opensmtpd-filter-greylistd
    go build
    sudo install opensmtpd-filter-greylistd /usr/libexec/opensmtpd/filter-greylistd


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
.. _bug992064: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=992064
