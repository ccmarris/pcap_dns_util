#!/usr/bin/env python3
#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''

 Description:

    CLI interface for pcap_dns_report

 Requirements:
   Python3 with scapy

 Author: Chris Marrison

 Date Last Updated: 20240302

 Todo:

 Copyright (c) 2024 Chris Marrison / Infoblox

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
import pcap_dns_util
import argparse
import logging
import sys
from rich import print

__version__ = '0.0.3'
__copyright__ = "Chris Marrison"
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'
__license__ = 'BSD-2-Clause'


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

    parser.add_argument('-p', '--pcap', type=str, default='sample_queries',
                        help="PCAP input file")

    parser.add_argument('-i', '--ignore_list', type=str, default='ignore_list',
                        help="Ignore domains input file")

    parser.add_argument('-o', '--output', type=str, default='',
                         help="Output files using prefix (including path)")

    parser.add_argument('-f', '--filtered', action='store_true',
                        help="Ouput filtered domains only")

    parser.add_argument('-S', '--silent', action='store_true',
                        help="Silent")

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


def main():
    '''
    Core script logic
    '''
    # Local Variables
    exitcode = 0

    args = parse_args()

    # Set up logging
    # log = setup_logging(args.debug)
    
    pcap = pcap_dns_util.PCAP_DNS(pcap_file=args.pcap,
                                    ignore_file=args.ignore_list)
    report = pcap.process_pcap()

    if args.output:
        logging.info(f'Outputting reports using prefix {args.output}')
        pcap.output_statistics(report, file=True, prefix=args.output)
        pcap.output_filtered(report, file=True, prefix=args.output)

    elif args.filtered:
        pcap.output_filtered(report)
    else:
        pcap.output_statistics(report)

        print('Filtered FQDNs:')
        pcap.output_filtered(report)

    logging.debug("Processing complete.")

    return exitcode


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
### End Main ###
