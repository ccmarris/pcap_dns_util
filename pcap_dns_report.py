#!/usr/bin/env python3
#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''

 Description:

    Test pcap reader for DNS query data

 Requirements:
   Python3 with scapy

 Author: Chris Marrison

 Date Last Updated: 20240222

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
import logging
import sys
import os
import collections
import yaml
import tqdm
import bloxone

# Change scapy logging level to remove interface WARNINGS from scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import PcapReader, Scapy_Exception
from scapy.layers.dns import DNS,DNSQR,DNSRR


'''
# Fix Crypto Warnings from scapy
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
'''

__version__ = '0.0.8'
__copyright__ = "Chris Marrison"
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'
__license__ = 'BSD-2-Clause'

_logger = logging.getLogger(__name__)


class PCAP_DNS:
    '''
    Report on DNS queries in PCAP file

    Inputs:
        dns_qtypes.yaml: Contains query type definitions
        ignore_list: Contains list of 'domains' to ignore
    '''
    def __init__(self, pcap_file: str ='traffic.cap',
                         ignore_file: str ='ignore_list',
                       qtypes_file: str ='dns_qtypes.yaml'):
        '''
        '''
        qtype_cfg: dict
        self.qtype: dict
        self.ignore_list: list 

        qtype_cfg = self.read_qtypes(qtypes_file)
        self.qtype = qtype_cfg['qtype']
        self.qtype_version = qtype_cfg['version']

        self.ignore_list = self.read_ignore_list(ignore_file)
        try:
            self.pcap = open(pcap_file, 'rb')
            self.pcap_size = os.stat(pcap_file).st_size
            logging.info(f'Successfully opened pcap file {pcap_file}.')
        except IOError as err:
            logging.error(f'Failed to open {pcap_file}: {err}')
            raise

        return


    def read_qtypes(self, cfg:str):
        '''
        '''
        dns_cfg: dict

        if os.path.isfile(cfg):
            # Read yaml configuration file
            try:
                dns_cfg = yaml.safe_load(open(cfg, 'r'))
            except yaml.YAMLError as err:
                logging.error(err)
                raise
        else:
            logging.error(f'Query type (yaml) config file "{cfg}" not found.')
            logging.warning('Query types will not be translated')
            # Build simple 
            dns_cfg = { 'version': '0.0', 'qtype': {} }
            # for i in range(65535):
                # dns_cfg['qtype'].update({ i: str(i) })

        return dns_cfg


    def read_ignore_list(self, ignore_list:str):
        '''
        '''
        domains: list = []

        if os.path.isfile(ignore_list):
            # Read yaml configuration file
            try:
                f = open(ignore_list)
                for domain in f:
                    d = domain.strip()
                    # Check for trailing . and append if needed
                    if d[-1] != '.':
                        d += '.'
                    domains.append(d)
                f.close()

            except IOError as err:
                logging.error(err)
                raise
        else:
            logging.error(f'Ignore list file {ignore_list} not found, using default')
            domains = [ 'arpa.' ]

        return domains
    

    def get_qtype(self, qt:int = 0):
        '''
        Return qtype as string from integer

        Parameters:
            qt: int = integer DNS query type

        Returns:
            type: str = record type
        '''
        type:str = 'unknown'
        if qt in self.qtype.keys():
            type = self.qtype[qt]
        else:
            type = f'Type: {qt}'
        
        return type


    def internal_domain(self, fqdn):
        '''
        Check fqdn against list of domains in ignore_list

        Parameters:
            fqdn: str = fqdn to check
        
        Returns:
            bool
        '''
        status: bool = False
        flength: int = len(fqdn)

        for domain in self.ignore_list:
            dlength = len(domain)
            # Compare domain lengths
            if flength >= dlength:
                # Check whether FQDN belongs to the domain
                if fqdn[-dlength::] == domain:
                    status = True
                    # Stop checks on first match
                    break
                else:
                    status = False
            else:
                status = False
        
        return status


    def process_pcap(self, silent:bool = False):
        '''
        Process the pcap file

        Parameters:
            silent: bool = Suppress progress bar

        Returns:
            report: dict = Analysis report
        '''
        pcount: int = 0
        qcount: int = 0
        qname:str = ''
        all_fqdns = collections.Counter()
        query_types = collections.Counter()
        filtered_fqdns: set = set()
        report: dict = {}
        
        try:
            self.pcap.seek(0)
            logging.info('Opened PCAP, processing...')
            
            if not silent:
                pbar = tqdm.tqdm(total=self.pcap_size)
            for pkt in PcapReader(self.pcap):
                pcount += 1
                if not silent:
                    pbar.update(len(pkt))
                # Check for DNS Query
                if pkt.haslayer(DNSQR):
                    qcount += 1
                    # process_dns_pkt(pkt)
                    qname = str(pkt[DNSQR].qname.decode())
                    all_fqdns[qname] += 1
                    query_types[self.get_qtype(pkt[DNSQR].qtype)] += 1
                    if not self.internal_domain(fqdn=qname):
                        filtered_fqdns.add(qname)
            pbar.close()
            report.update({'total packets': pcount,
                           'total queries': qcount,
                           'unique_fqdns': dict(all_fqdns),
                           'record_types': dict(query_types),
                           'filtered_fqdns': filtered_fqdns })
        except:
            raise
            
        return report

    