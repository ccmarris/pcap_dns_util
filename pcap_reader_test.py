#!/usr/bin/env python3
#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''

 Description:

    Test pcap reader for DNS query data

 Requirements:
   Python3 with scapy

 Author: Chris Marrison

 Date Last Updated: 20230214

 Todo:

 Copyright (c) 2023 Chris Marrison / Infoblox

 Redistribution and use in source and binary forms,
 with or without modification, are permitted provided
 that the following conditions are met:

 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

'''
import argparse
import logging
import sys
import tqdm

# Fix Crypto Warnings from scapy
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Change scapy logging level to remove interface WARNINGS from scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import PcapReader, Scapy_Exception
from scapy.layers.dns import DNS, DNSQR

__version__ = '0.0.2'
__copyright__ = "Chris Marrison"
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'
__license__ = 'BSD-2-Clause'

_logger = logging.getLogger(__name__)

ignore_domains = [ 'int.kn' ]

def parse_args():
    """Parse command line parameters

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--help"]``).

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(description="PCAP read DNS traffic")
    parser.add_argument(
        "--version",
        action="version",
        version="{ver}".format(ver=__version__),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        help="set loglevel to INFO",
        action="store_const",
        const=logging.INFO,
    )
    parser.add_argument(
        "-vv",
        "--very-verbose",
        dest="loglevel",
        help="set loglevel to DEBUG",
        action="store_const",
        const=logging.DEBUG,
    )

    parser.add_argument('-i', '--infile', type=str, default='sample_queries',
                        help="PCAP input file")


    return parser.parse_args()


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(
        level=loglevel, stream=sys.stdout, format=logformat, datefmt="%Y-%m-%d %H:%M:%S"
    )
    return


def internal_domain(query: str, int_domains: list = []) -> bool:
    '''
    '''
    status = False
    for id in int_domains:
        if id in query:
            status = True
            break
    
    return status


def process_pcap(filename: str = 'test.pcap', int_domains: list = []):
    '''
    '''
    pcount = 0
    queries = []
    types = { 0: 'ANY', 255: 'ALL',1: 'A', 2: 'NS', 3: 'MD', 4: 'MD', 
              5: 'CNAME', 6: 'SOA', 7:  'MB',8: 'MG',9: 'MR',10: 'NULL',
              11: 'WKS', 12: 'PTR', 13: 'HINFO', 14: 'MINFO', 15: 'MX', 
              16: 'TXT', 17: 'RP', 18: 'AFSDB', 28: 'AAAA', 33: 'SRV', 
              38: 'A6', 39: 'DNAME', 65: 'HTTPS' }

    dns_packets = PcapReader(filename)
    for packet in dns_packets:
        pcount += 1
    dns_packets = PcapReader(filename)
    with tqdm.tqdm(total=pcount) as pbar:
        for packet in dns_packets:
            pbar.update(1)
            if packet.haslayer(DNS):
                # print(packet.show())
                #dst = packet['IP'].dst
                qrystr = packet[DNSQR].qname.decode()
                if not internal_domain(query=qrystr, int_domains=int_domains):
                    rec_type = packet[DNSQR].qtype
                    queries.append(f'{qrystr} {types.get(rec_type)}')
    print(queries)
        
    return


def main():
    '''
    Core script logic
    '''
    # Local Variables
    exitcode = 0

    args = parse_args()

    # Set up logging
    # log = setup_logging(args.debug)

    process_pcap(args.infile, int_domains=ignore_domains)
    loggging.debug("Processing complete.")

    return exitcode


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
### End Main ###
