"""
DHCP Server Module (Optional)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional DHCP server integration for Pidanos.
"""

import logging
import socket
import struct
import asyncio
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
import json

logger = logging.getLogger(__name__)


class DHCPLease:
    """Represents a DHCP lease"""
    
    def __init__(self, mac_address: str, ip_address: str, hostname: Optional[str] = None,
                 lease_time: int = 86400):
        self.mac_address = mac_address.upper()
        self.ip_address = ip_address
        self.hostname = hostname
        self.lease_time = lease_time
        self.created_at = datetime.now()
        self.expires_at = self.created_at + timedelta(seconds=lease_time)
        
    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at
        
    def renew(self, lease_time: Optional[int] = None):
        """Renew the lease"""
        if lease_time:
            self.lease_time = lease_time
        self.expires_at = datetime.now() + timedelta(seconds=self.lease_time)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'mac_address': self.mac_address,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'lease_time': self.lease_time,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat()
        }


class DHCPServer:
    """Optional DHCP server for Pidanos"""
    
    # DHCP message types
    DHCP_DISCOVER = 1
    DHCP_OFFER = 2
    DHCP_REQUEST = 3
    DHCP_DECLINE = 4
    DHCP_ACK = 5
    DHCP_NAK = 6
    DHCP_RELEASE = 7
    DHCP_INFORM = 8
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('features', {}).get('dhcp', {}).get('enabled', False)
        
        if not self.enabled:
            logger.info("DHCP server is disabled")
            return
            
        # Network configuration
        dhcp_config = config['features']['dhcp']
        self.interface = dhcp_config.get('interface', 'eth0')
        self.server_ip = dhcp_config.get('server_ip', '192.168.1.1')
        self.network = IPv4Network(dhcp_config.get('network', '192.168.1.0/24'))
        
        # DHCP pool
        self.pool_start = IPv4Address(dhcp_config.get('pool_start', '192.168.1.100'))
        self.pool_end = IPv4Address(dhcp_config.get('pool_end', '192.168.1.200'))
        
        # DHCP options
        self.lease_time = dhcp_config.get('lease_time', 86400)  # 24 hours
        self.dns_servers = dhcp_config.get('dns_servers', [self.server_ip])
        self.gateway = dhcp_config.get('gateway', self.server_ip)
        self.domain_name = dhcp_config.get('domain_name', 'local')
        
        # Lease management
        self.leases: Dict[str, DHCPLease] = {}  # MAC -> Lease
        self.ip_assignments: Dict[str, str] = {}  # IP -> MAC
        self.static_leases: Dict[str, str] = {}  # MAC -> IP
        
        # Load static leases
        for lease in dhcp_config.get('static_leases', []):
            self.static_leases[lease['mac'].upper()] = lease['ip']
            
        # Server socket
        self.socket: Optional[socket.socket] = None
        self.running = False
        
    async def start(self):
        """Start DHCP server"""
        if not self.enabled:
            return
            
        logger.info(f"Starting DHCP server on {self.interface}")
        
        # Create socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Bind to DHCP server port
        self.socket.bind(('', 67))
        self.socket.setblocking(False)
        
        self.running = True
        
        # Start server loop
        asyncio.create_task(self._server_loop())
        
        # Start lease cleanup task
        asyncio.create_task(self._cleanup_expired_leases())
        
        logger.info("DHCP server started")
        
    async def stop(self):
        """Stop DHCP server"""
        if not self.enabled:
            return
            
        logger.info("Stopping DHCP server")
        self.running = False
        
        if self.socket:
            self.socket.close()
            
        # Save leases
        await self._save_leases()
        
    async def _server_loop(self):
        """Main DHCP server loop"""
        loop = asyncio.get_event_loop()
        
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.socket, 1024)
                
                # Process DHCP packet
                asyncio.create_task(self._handle_dhcp_packet(data, addr))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"DHCP server error: {e}")
                
    async def _handle_dhcp_packet(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming DHCP packet"""
        try:
            # Parse DHCP packet
            packet = self._parse_dhcp_packet(data)
            if not packet:
                return
                
            message_type = packet.get('message_type')
            mac_address = packet.get('mac_address')
            
            logger.debug(f"DHCP {message_type} from {mac_address}")
            
            # Handle based on message type
            if message_type == self.DHCP_DISCOVER:
                await self._handle_discover(packet)
            elif message_type == self.DHCP_REQUEST:
                await self._handle_request(packet)
            elif message_type == self.DHCP_RELEASE:
                await self._handle_release(packet)
            elif message_type == self.DHCP_INFORM:
                await self._handle_inform(packet)
                
        except Exception as e:
            logger.error(f"Error handling DHCP packet: {e}")
            
    def _parse_dhcp_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DHCP packet"""
        if len(data) < 240:
            return None
            
        # Unpack fixed portion
        (op, htype, hlen, hops, xid, secs, flags,
         ciaddr, yiaddr, siaddr, giaddr) = struct.unpack('!BBBBIHH4s4s4s4s', data[:28])
         
        # Extract MAC address
        chaddr = data[28:28+16]
        mac_bytes = chaddr[:hlen]
        mac_address = ':'.join(f'{b:02X}' for b in mac_bytes)
        
        # Skip server name and boot file
        options_start = 236
        
        # Check for magic cookie
        if data[options_start:options_start+4] != b'\x63\x82\x53\x63':
            return None
            
        # Parse options
        options = {}
        i = options_start + 4
        
        while i < len(data):
            if data[i] == 255:  # End option
                break
            elif data[i] == 0:  # Pad option
                i += 1
                continue
                
            opt_type = data[i]
            opt_len = data[i + 1]
            opt_data = data[i + 2:i + 2 + opt_len]
            
            options[opt_type] = opt_data
            i += 2 + opt_len
            
        # Get message type
        message_type = None
        if 53 in options:  # DHCP Message Type
            message_type = options[53][0]
            
        return {
            'op': op,
            'xid': xid,
            'mac_address': mac_address,
            'ciaddr': socket.inet_ntoa(ciaddr),
            'options': options,
            'message_type': message_type
        }
        
    async def _handle_discover(self, packet: Dict[str, Any]):
        """Handle DHCP DISCOVER"""
        mac_address = packet['mac_address']
        
        # Allocate IP address
        ip_address = await self._allocate_ip(mac_address)
        if not ip_address:
            logger.warning(f"No IP available for {mac_address}")
            return
            
        # Send DHCP OFFER
        response = self._build_dhcp_packet(
            self.DHCP_OFFER,
            packet['xid'],
            mac_address,
            ip_address
        )
        
        await self._send_dhcp_packet(response)
        logger.info(f"Sent DHCP OFFER to {mac_address}: {ip_address}")
        
    async def _handle_request(self, packet: Dict[str, Any]):
        """Handle DHCP REQUEST"""
        mac_address = packet['mac_address']
        
        # Get requested IP
        requested_ip = None
        if 50 in packet['options']:  # Requested IP Address
            requested_ip = socket.inet_ntoa(packet['options'][50])
            
        # Validate and assign IP
        if requested_ip and await self._can_assign_ip(mac_address, requested_ip):
            ip_address = requested_ip
        else:
            ip_address = await self._allocate_ip(mac_address)
            
        if not ip_address:
            # Send DHCP NAK
            response = self._build_dhcp_packet(
                self.DHCP_NAK,
                packet['xid'],
                mac_address,
                '0.0.0.0'
            )
            await self._send_dhcp_packet(response)
            return
            
        # Create or update lease
        hostname = None
        if 12 in packet['options']:  # Hostname
            hostname = packet['options'][12].decode('utf-8', errors='ignore')
            
        lease = DHCPLease(mac_address, ip_address, hostname, self.lease_time)
        self.leases[mac_address] = lease
        self.ip_assignments[ip_address] = mac_address
        
        # Send DHCP ACK
        response = self._build_dhcp_packet(
            self.DHCP_ACK,
            packet['xid'],
            mac_address,
            ip_address
        )
        
        await self._send_dhcp_packet(response)
        logger.info(f"Sent DHCP ACK to {mac_address}: {ip_address}")
        
    async def _handle_release(self, packet: Dict[str, Any]):
        """Handle DHCP RELEASE"""
        mac_address = packet['mac_address']
        
        if mac_address in self.leases:
            lease = self.leases[mac_address]
            del self.ip_assignments[lease.ip_address]
            del self.leases[mac_address]
            
            logger.info(f"Released lease for {mac_address}: {lease.ip_address}")
            
    async def _handle_inform(self, packet: Dict[str, Any]):
        """Handle DHCP INFORM"""
        # Client already has IP, just wants configuration
        mac_address = packet['mac_address']
        
        response = self._build_dhcp_packet(
            self.DHCP_ACK,
            packet['xid'],
            mac_address,
            packet['ciaddr'],
            skip_lease=True
        )
        
        await self._send_dhcp_packet(response)
        
    async def _allocate_ip(self, mac_address: str) -> Optional[str]:
        """Allocate IP address for MAC"""
        # Check static assignment
        if mac_address in self.static_leases:
            return self.static_leases[mac_address]
            
        # Check existing lease
        if mac_address in self.leases:
            lease = self.leases[mac_address]
            if not lease.is_expired:
                return lease.ip_address
                
        # Find available IP in pool
        for ip_int in range(int(self.pool_start), int(self.pool_end) + 1):
            ip_str = str(IPv4Address(ip_int))
            
            if ip_str not in self.ip_assignments:
                return ip_str
                
        return None
        
    async def _can_assign_ip(self, mac_address: str, ip_address: str) -> bool:
        """Check if IP can be assigned to MAC"""
        # Check if IP is in pool
        ip = IPv4Address(ip_address)
        if ip < self.pool_start or ip > self.pool_end:
            return False
            
        # Check if IP is already assigned
        if ip_address in self.ip_assignments:
            return self.ip_assignments[ip_address] == mac_address
            
        return True
        
    def _build_dhcp_packet(self, message_type: int, xid: int, 
                          mac_address: str, ip_address: str,
                          skip_lease: bool = False) -> bytes:
        """Build DHCP response packet"""
        # Fixed portion
        packet = struct.pack('!BBBBIHH',
            2,      # op: BOOTREPLY
            1,      # htype: Ethernet
            6,      # hlen: MAC address length
            0,      # hops
            xid,    # xid
            0,      # secs
            0       # flags
        )
        
        # Addresses
        packet += socket.inet_aton('0.0.0.0')  # ciaddr
        packet += socket.inet_aton(ip_address)  # yiaddr
        packet += socket.inet_aton(self.server_ip)  # siaddr
        packet += socket.inet_aton('0.0.0.0')  # giaddr
        
        # MAC address (chaddr)
        mac_bytes = bytes.fromhex(mac_address.replace(':', ''))
        packet += mac_bytes + b'\x00' * (16 - len(mac_bytes))
        
        # Server name and boot file
        packet += b'\x00' * 64  # sname
        packet += b'\x00' * 128  # file
        
        # Magic cookie
        packet += b'\x63\x82\x53\x63'
        
        # DHCP options
        options = bytearray()
        
        # Message type
        options.extend([53, 1, message_type])
        
        # Server identifier
        options.extend([54, 4])
        options.extend(socket.inet_aton(self.server_ip))
        
        if not skip_lease:
            # Lease time
            options.extend([51, 4])
            options.extend(struct.pack('!I', self.lease_time))
            
            # Subnet mask
            options.extend([1, 4])
            options.extend(self.network.netmask.packed)
            
            # Router
            options.extend([3, 4])
            options.extend(socket.inet_aton(self.gateway))
            
            # DNS servers
            options.extend([6, len(self.dns_servers) * 4])
            for dns in self.dns_servers:
                options.extend(socket.inet_aton(dns))
                
            # Domain name
            if self.domain_name:
                domain_bytes = self.domain_name.encode('utf-8')
                options.extend([15, len(domain_bytes)])
                options.extend(domain_bytes)
                
        # End option
        options.append(255)
        
        packet += bytes(options)
        
        # Pad to minimum size
        if len(packet) < 300:
            packet += b'\x00' * (300 - len(packet))
            
        return packet
        
    async def _send_dhcp_packet(self, packet: bytes):
        """Send DHCP packet"""
        loop = asyncio.get_event_loop()
        
        # Send as broadcast
        await loop.sock_sendto(self.socket, packet, ('255.255.255.255', 68))
        
    async def _cleanup_expired_leases(self):
        """Periodically cleanup expired leases"""
        while self.running:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                expired = []
                for mac, lease in self.leases.items():
                    if lease.is_expired:
                        expired.append(mac)
                        
                for mac in expired:
                    lease = self.leases[mac]
                    del self.ip_assignments[lease.ip_address]
                    del self.leases[mac]
                    logger.info(f"Expired lease for {mac}: {lease.ip_address}")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Lease cleanup error: {e}")
                
    async def _save_leases(self):
        """Save current leases to file"""
        lease_file = self.config.get('general', {}).get('data_dir', '/var/lib/pidanos') + '/dhcp_leases.json'
        
        try:
            leases_data = {
                mac: lease.to_dict() 
                for mac, lease in self.leases.items()
            }
            
            with open(lease_file, 'w') as f:
                json.dump(leases_data, f, indent=2)
                
            logger.info(f"Saved {len(leases_data)} DHCP leases")
            
        except Exception as e:
            logger.error(f"Failed to save DHCP leases: {e}")
            
    async def _load_leases(self):
        """Load saved leases from file"""
        lease_file = self.config.get('general', {}).get('data_dir', '/var/lib/pidanos') + '/dhcp_leases.json'
        
        try:
            if os.path.exists(lease_file):
                with open(lease_file, 'r') as f:
                    leases_data = json.load(f)
                    
                for mac, lease_dict in leases_data.items():
                    # Recreate lease if not expired
                    expires_at = datetime.fromisoformat(lease_dict['expires_at'])
                    if expires_at > datetime.now():
                        lease = DHCPLease(
                            mac,
                            lease_dict['ip_address'],
                            lease_dict.get('hostname'),
                            lease_dict['lease_time']
                        )
                        lease.created_at = datetime.fromisoformat(lease_dict['created_at'])
                        lease.expires_at = expires_at
                        
                        self.leases[mac] = lease
                        self.ip_assignments[lease.ip_address] = mac
                        
                logger.info(f"Loaded {len(self.leases)} DHCP leases")
                
        except Exception as e:
            logger.error(f"Failed to load DHCP leases: {e}")
            
    def get_active_leases(self) -> List[Dict[str, Any]]:
        """Get list of active leases"""
        active_leases = []
        
        for lease in self.leases.values():
            if not lease.is_expired:
                active_leases.append(lease.to_dict())
                
        return active_leases
        
    def get_lease_by_mac(self, mac_address: str) -> Optional[DHCPLease]:
        """Get lease by MAC address"""
        return self.leases.get(mac_address.upper())
        
    def get_lease_by_ip(self, ip_address: str) -> Optional[DHCPLease]:
        """Get lease by IP address"""
        mac = self.ip_assignments.get(ip_address)
        if mac:
            return self.leases.get(mac)
        return None