"""
DNS Parser Module
~~~~~~~~~~~~~~~~~

Parse and construct DNS packets for the Pidanos DNS server.
"""

import struct
import logging
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import IntEnum

logger = logging.getLogger(__name__)


class DNSType(IntEnum):
    """DNS query types"""
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    OPT = 41
    ANY = 255


class DNSClass(IntEnum):
    """DNS query classes"""
    IN = 1
    CS = 2
    CH = 3
    HS = 4
    ANY = 255


class DNSResponseCode(IntEnum):
    """DNS response codes"""
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


@dataclass
class DNSHeader:
    """DNS packet header"""
    id: int
    flags: int
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0
    
    @property
    def qr(self) -> bool:
        """Query/Response flag"""
        return bool(self.flags & 0x8000)
        
    @qr.setter
    def qr(self, value: bool):
        if value:
            self.flags |= 0x8000
        else:
            self.flags &= ~0x8000
            
    @property
    def opcode(self) -> int:
        """Operation code"""
        return (self.flags >> 11) & 0xF
        
    @property
    def aa(self) -> bool:
        """Authoritative Answer flag"""
        return bool(self.flags & 0x0400)
        
    @aa.setter
    def aa(self, value: bool):
        if value:
            self.flags |= 0x0400
        else:
            self.flags &= ~0x0400
            
    @property
    def tc(self) -> bool:
        """Truncation flag"""
        return bool(self.flags & 0x0200)
        
    @property
    def rd(self) -> bool:
        """Recursion Desired flag"""
        return bool(self.flags & 0x0100)
        
    @property
    def ra(self) -> bool:
        """Recursion Available flag"""
        return bool(self.flags & 0x0080)
        
    @ra.setter
    def ra(self, value: bool):
        if value:
            self.flags |= 0x0080
        else:
            self.flags &= ~0x0080
            
    @property
    def rcode(self) -> int:
        """Response code"""
        return self.flags & 0xF
        
    @rcode.setter
    def rcode(self, value: int):
        self.flags = (self.flags & ~0xF) | (value & 0xF)
        
    def to_bytes(self) -> bytes:
        """Convert header to bytes"""
        return struct.pack('!HHHHHH', 
                         self.id, self.flags, 
                         self.qdcount, self.ancount, 
                         self.nscount, self.arcount)
                         
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DNSHeader':
        """Parse header from bytes"""
        if len(data) < 12:
            raise ValueError("Invalid DNS header length")
            
        fields = struct.unpack('!HHHHHH', data[:12])
        return cls(*fields)


@dataclass
class DNSQuestion:
    """DNS question section"""
    qname: str
    qtype: int
    qclass: int = DNSClass.IN
    
    def to_bytes(self) -> bytes:
        """Convert question to bytes"""
        # Encode domain name
        labels = self.qname.split('.')
        qname_bytes = b''
        
        for label in labels:
            if label:
                qname_bytes += bytes([len(label)]) + label.encode('ascii')
                
        qname_bytes += b'\x00'  # Root label
        
        # Add type and class
        return qname_bytes + struct.pack('!HH', self.qtype, self.qclass)
        
    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Tuple['DNSQuestion', int]:
        """Parse question from bytes"""
        # Parse domain name
        qname, new_offset = DNSParser._parse_domain_name(data, offset)
        
        # Parse type and class
        if new_offset + 4 > len(data):
            raise ValueError("Invalid DNS question")
            
        qtype, qclass = struct.unpack('!HH', data[new_offset:new_offset + 4])
        
        return cls(qname, qtype, qclass), new_offset + 4


@dataclass
class DNSAnswer:
    """DNS answer/resource record"""
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    
    @property
    def rdlength(self) -> int:
        """Resource data length"""
        return len(self.rdata)
        
    def to_bytes(self, compression_map: Optional[Dict[str, int]] = None) -> bytes:
        """Convert answer to bytes with optional compression"""
        # Encode name (with compression if available)
        if compression_map and self.name in compression_map:
            name_bytes = struct.pack('!H', 0xC000 | compression_map[self.name])
        else:
            labels = self.name.split('.')
            name_bytes = b''
            for label in labels:
                if label:
                    name_bytes += bytes([len(label)]) + label.encode('ascii')
            name_bytes += b'\x00'
            
        # Add type, class, TTL, and data
        header = struct.pack('!HHIH', self.rtype, self.rclass, self.ttl, self.rdlength)
        
        return name_bytes + header + self.rdata
        
    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Tuple['DNSAnswer', int]:
        """Parse answer from bytes"""
        # Parse name
        name, new_offset = DNSParser._parse_domain_name(data, offset)
        
        # Parse fixed fields
        if new_offset + 10 > len(data):
            raise ValueError("Invalid DNS answer")
            
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[new_offset:new_offset + 10])
        new_offset += 10
        
        # Parse resource data
        if new_offset + rdlength > len(data):
            raise ValueError("Invalid DNS answer data")
            
        rdata = data[new_offset:new_offset + rdlength]
        
        return cls(name, rtype, rclass, ttl, rdata), new_offset + rdlength


class DNSParser:
    """DNS packet parser and constructor"""
    
    @staticmethod
    def parse_packet(data: bytes) -> Dict:
        """Parse a complete DNS packet"""
        if len(data) < 12:
            raise ValueError("DNS packet too short")
            
        # Parse header
        header = DNSHeader.from_bytes(data)
        offset = 12
        
        # Parse questions
        questions = []
        for _ in range(header.qdcount):
            question, offset = DNSQuestion.from_bytes(data, offset)
            questions.append(question)
            
        # Parse answers
        answers = []
        for _ in range(header.ancount):
            answer, offset = DNSAnswer.from_bytes(data, offset)
            answers.append(answer)
            
        # Parse authority records
        authority = []
        for _ in range(header.nscount):
            record, offset = DNSAnswer.from_bytes(data, offset)
            authority.append(record)
            
        # Parse additional records
        additional = []
        for _ in range(header.arcount):
            record, offset = DNSAnswer.from_bytes(data, offset)
            additional.append(record)
            
        return {
            'header': header,
            'questions': questions,
            'answers': answers,
            'authority': authority,
            'additional': additional
        }
        
    @staticmethod
    def build_response(query_packet: Dict, answers: List[DNSAnswer], 
                      rcode: DNSResponseCode = DNSResponseCode.NOERROR) -> bytes:
        """Build a DNS response packet"""
        header = query_packet['header']
        
        # Create response header
        response_header = DNSHeader(
            id=header.id,
            flags=header.flags,
            qdcount=len(query_packet['questions']),
            ancount=len(answers),
            nscount=0,
            arcount=0
        )
        
        # Set response flags
        response_header.qr = True  # This is a response
        response_header.aa = True  # We are authoritative
        response_header.ra = True  # Recursion available
        response_header.rcode = rcode
        
        # Build packet
        packet = response_header.to_bytes()
        
        # Add questions
        for question in query_packet['questions']:
            packet += question.to_bytes()
            
        # Build compression map for efficient encoding
        compression_map = {}
        
        # Add answers with compression
        for answer in answers:
            packet += answer.to_bytes(compression_map)
            # Add to compression map
            if len(packet) < 16384:  # Only compress if packet is small enough
                compression_map[answer.name] = 12  # Offset to first question
                
        return packet
        
    @staticmethod
    def build_nxdomain_response(query_packet: Dict) -> bytes:
        """Build an NXDOMAIN response"""
        return DNSParser.build_response(query_packet, [], DNSResponseCode.NXDOMAIN)
        
    @staticmethod
    def build_blocked_response(query_packet: Dict, block_ip: str = "0.0.0.0") -> bytes:
        """Build a response for blocked domains"""
        answers = []
        
        for question in query_packet['questions']:
            if question.qtype == DNSType.A:
                # Build A record
                rdata = DNSParser._ip4_to_bytes(block_ip)
                answer = DNSAnswer(
                    name=question.qname,
                    rtype=DNSType.A,
                    rclass=DNSClass.IN,
                    ttl=0,  # Don't cache blocked responses
                    rdata=rdata
                )
                answers.append(answer)
            elif question.qtype == DNSType.AAAA:
                # Build AAAA record for IPv6
                rdata = DNSParser._ip6_to_bytes("::")
                answer = DNSAnswer(
                    name=question.qname,
                    rtype=DNSType.AAAA,
                    rclass=DNSClass.IN,
                    ttl=0,
                    rdata=rdata
                )
                answers.append(answer)
                
        return DNSParser.build_response(query_packet, answers)
        
    @staticmethod
    def _parse_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
        """Parse a domain name from DNS packet"""
        labels = []
        original_offset = offset
        jumped = False
        
        while offset < len(data):
            length = data[offset]
            
            if length == 0:
                # End of domain name
                offset += 1
                break
            elif length & 0xC0 == 0xC0:
                # Compression pointer
                if not jumped:
                    original_offset = offset + 2
                    
                pointer = struct.unpack('!H', data[offset:offset + 2])[0]
                offset = pointer & 0x3FFF
                jumped = True
            else:
                # Regular label
                offset += 1
                if offset + length > len(data):
                    raise ValueError("Invalid domain name")
                    
                label = data[offset:offset + length].decode('ascii')
                labels.append(label)
                offset += length
                
        domain = '.'.join(labels)
        return domain, original_offset if jumped else offset
        
    @staticmethod
    def _ip4_to_bytes(ip_str: str) -> bytes:
        """Convert IPv4 address string to bytes"""
        parts = ip_str.split('.')
        if len(parts) != 4:
            raise ValueError("Invalid IPv4 address")
            
        return bytes(int(part) for part in parts)
        
    @staticmethod
    def _ip6_to_bytes(ip_str: str) -> bytes:
        """Convert IPv6 address string to bytes"""
        import ipaddress
        try:
            addr = ipaddress.IPv6Address(ip_str)
            return addr.packed
        except ipaddress.AddressValueError:
            raise ValueError("Invalid IPv6 address")
            
    @staticmethod
    def extract_query_info(packet: Dict) -> Dict[str, Union[str, int]]:
        """Extract useful information from a DNS query"""
        if not packet['questions']:
            return {}
            
        question = packet['questions'][0]
        
        return {
            'domain': question.qname,
            'type': DNSParser._type_to_string(question.qtype),
            'type_id': question.qtype,
            'class': DNSParser._class_to_string(question.qclass),
            'id': packet['header'].id
        }
        
    @staticmethod
    def _type_to_string(qtype: int) -> str:
        """Convert DNS type to string"""
        try:
            return DNSType(qtype).name
        except ValueError:
            return f"TYPE{qtype}"
            
    @staticmethod
    def _class_to_string(qclass: int) -> str:
        """Convert DNS class to string"""
        try:
            return DNSClass(qclass).name
        except ValueError:
            return f"CLASS{qclass}"