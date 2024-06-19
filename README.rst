=======================================
Utility to analyse DNS from a PCAP File
=======================================

| Version: 0.1.0
| Author: Chris Marrison
| Email: chris@infoblox.com

Description
-----------

Provides a simple python class to process DNS packets in a PCAP file
using scapy. 

Demonstration code is included that enables this to be used as a simple 
script.


Prerequisites
-------------

Python 3.8+


Installing Python
~~~~~~~~~~~~~~~~~

You can install the latest version of Python 3.x by downloading the appropriate
installer for your system from `python.org <https://python.org>`_.

.. note::

  If you are running MacOS Catalina (or later) Python 3 comes pre-installed.
  Previous versions only come with Python 2.x by default and you will therefore
  need to install Python 3 as above or via Homebrew, Ports, etc.

  By default the python command points to Python 2.x, you can check this using 
  the command::

    $ python -V

  To specifically run Python 3, use the command::

    $ python3


.. important::

  Mac users will need the xcode command line utilities installed to use pip3,
  etc. If you need to install these use the command::

    $ xcode-select --install

.. note::

  If you are installing Python on Windows, be sure to check the box to have 
  Python added to your PATH if the installer offers such an option 
  (it's normally off by default).


Modules
~~~~~~~

Non-standard modules:

    - scapy 
    - tqdm
    - yaml


Configuration 
~~~~~~~~~~~~~

Installation
------------

The simplest way to install and maintain the tools is to clone this 
repository::

    % git clone https://github.com/ccmarris/pcap_dns_util


Alternative you can download as a Zip file.


Basic Configuration
-------------------


Usage
-----

The script supports -h or --help on the command line to access the options 
available::


  % ./process_dns_pcap.py -h
  usage: process_dns_pcap.py [-h] [--version] [-v] [-vv] [-p PCAP] [-i IGNORE_LIST] [-o OUTPUT] [-f] [-S] [-r]

  PCAP read DNS traffic

  options:
    -h, --help            show this help message and exit
    --version             show program's version number and exit
    -v, --verbose         set loglevel to INFO
    -vv, --very-verbose   set loglevel to DEBUG
    -p PCAP, --pcap PCAP  PCAP input file
    -i IGNORE_LIST, --ignore_list IGNORE_LIST
                          Ignore domains input file
    -o OUTPUT, --output OUTPUT
                          Output files using prefix (including path)
    -f, --filtered        Ouput filtered domains only
    -S, --silent          Silent
    -r, --raw             RAW report


nios_fixed_addr_util
~~~~~~~~~~~~~~~~~~~~


Examples
--------

Simple Report on Fixed Address::

  % ./nios_fixed_addr_util.py --config gm.ini 


Enable debug::

  % ./nios_fixed_addr_util.py --config gm.ini --debug


Filter report::

  % ./nios_fixed_addr_util.py --config gm.ini --match_use 'False'
  % ./nios_fixed_addr_util.py --config gm.ini --match_use 'True'
  % ./nios_fixed_addr_util.py --config gm.ini --match_use 'Reserved'
  % ./nios_fixed_addr_util.py --config gm.ini --match_use 'Unknown'


Output to file::

  % ./nios_fixed_addr_util.py --config gm.ini --file fa-report.csv


Add/update Extensible Attribute on fixed address objects in NIOS:

  % ./nios_fixed_addr_util.py --config gm.ini --update


Use an alternate EA name from default (with auto create)::

  % ./nios_fixed_addr_util.py --config gm.ini --update --ea_name 'Lease_status' --auto



License
-------

This project is licensed under the 2-Clause BSD License
- please see LICENSE file for details.


Aknowledgements
---------------

Thanks to Steve Salo for some testing and debugging data issues.
