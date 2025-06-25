"""
DNS Blocker Core Engine
~~~~~~~~~~~~~~~~~~~~~~~

Main blocking functionality for Pidanos DNS filtering.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re

logger = logging.getLogger(__name__)


class BlockType(Enum):
    """Types of blocking methods"""
    EXACT = "exact"
    REGEX = "regex"
    WILDCARD = "wildcard"
    CNAME = "cname"


class BlockAction(Enum):
    """Actions to take when blocking"""
    NULL_IP = "0.0.0.0"
    NULL_IPV6 = "::"
    NXDOMAIN = "nxdomain"
    CUSTOM_IP = "custom"


@dataclass
class BlockRule:
    """Represents a single blocking rule"""
    domain: str
    block_type: BlockType
    source: str
    regex_pattern: Optional[re.Pattern] = None
    added_timestamp: float = 0
    hit_count: int = 0


@dataclass
class QueryResult:
    """Result of a DNS query check"""
    blocked: bool
    reason: Optional[str] = None
    block_type: Optional[BlockType] = None
    response_ip: Optional[str] = None
    matched_rule: Optional[str] = None


class DNSBlocker:
    """Main DNS blocking engine"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.blocklist: Dict[str, BlockRule] = {}
        self.whitelist: Set[str] = set()
        self.regex_rules: List[BlockRule] = []
        self.wildcard_rules: Dict[str, BlockRule] = {}
        self.block_action = BlockAction(config.get('block_action', 'NULL_IP'))
        self.custom_block_ip = config.get('custom_block_ip', '127.0.0.1')
        self._lock = asyncio.Lock()
        self.stats = {
            'total_queries': 0,
            'blocked_queries': 0,
            'whitelisted_queries': 0
        }
        
    async def initialize(self):
        """Initialize the blocker with configuration"""
        logger.info("Initializing DNS Blocker...")
        await self.load_blocklists()
        await self.load_whitelist()
        await self.compile_regex_rules()
        logger.info(f"Blocker initialized with {len(self.blocklist)} blocked domains")
        
    async def load_blocklists(self):
        """Load blocking rules from various sources"""
        async with self._lock:
            # This would load from database or files
            # For now, adding some example entries
            self.blocklist.clear()
            
            # Example blocked domains
            example_blocks = [
                "doubleclick.net",
                "googleadservices.com",
                "googlesyndication.com",
                "google-analytics.com",
                "amazon-adsystem.com",
                "facebook.com/tr",
                "analytics.twitter.com"
            ]
            
            for domain in example_blocks:
                self.blocklist[domain] = BlockRule(
                    domain=domain,
                    block_type=BlockType.EXACT,
                    source="default",
                    added_timestamp=time.time()
                )
                
    async def load_whitelist(self):
        """Load whitelist entries"""
        async with self._lock:
            # Load from configuration or database
            self.whitelist.clear()
            
            # Default whitelist entries
            default_whitelist = [
                "localhost",
                "localhost.localdomain",
                "local",
                "broadcasthost",
                "ip6-localhost",
                "ip6-loopback"
            ]
            
            self.whitelist.update(default_whitelist)
            
    async def compile_regex_rules(self):
        """Compile regex patterns for efficient matching"""
        async with self._lock:
            self.regex_rules.clear()
            
            # Example regex patterns
            regex_patterns = [
                r"^ad[sz]?\d*\..*",  # ads, adsN, adzN
                r"^banner[sz]?\..*",  # banners
                r"^track(er|ing)?\..*",  # tracking
                r".*\.(doubleclick|googleadservices|googlesyndication)\..*"
            ]
            
            for pattern in regex_patterns:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    rule = BlockRule(
                        domain=pattern,
                        block_type=BlockType.REGEX,
                        source="regex",
                        regex_pattern=compiled,
                        added_timestamp=time.time()
                    )
                    self.regex_rules.append(rule)
                except re.error as e:
                    logger.error(f"Invalid regex pattern {pattern}: {e}")
                    
    async def check_domain(self, domain: str, client_ip: str = None) -> QueryResult:
        """Check if a domain should be blocked"""
        self.stats['total_queries'] += 1
        
        # Normalize domain
        domain = domain.lower().strip('.')
        
        # Check whitelist first
        if await self.is_whitelisted(domain):
            self.stats['whitelisted_queries'] += 1
            return QueryResult(blocked=False, reason="whitelisted")
            
        # Check exact match
        if domain in self.blocklist:
            self.stats['blocked_queries'] += 1
            rule = self.blocklist[domain]
            rule.hit_count += 1
            return QueryResult(
                blocked=True,
                reason="exact_match",
                block_type=BlockType.EXACT,
                response_ip=self._get_block_response(),
                matched_rule=domain
            )
            
        # Check wildcard rules
        wildcard_result = await self._check_wildcard(domain)
        if wildcard_result.blocked:
            self.stats['blocked_queries'] += 1
            return wildcard_result
            
        # Check regex rules
        regex_result = await self._check_regex(domain)
        if regex_result.blocked:
            self.stats['blocked_queries'] += 1
            return regex_result
            
        # Check parent domains
        parent_result = await self._check_parent_domains(domain)
        if parent_result.blocked:
            self.stats['blocked_queries'] += 1
            return parent_result
            
        # Not blocked
        return QueryResult(blocked=False)
        
    async def is_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted"""
        if domain in self.whitelist:
            return True
            
        # Check parent domains in whitelist
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.whitelist:
                return True
                
        return False
        
    async def _check_wildcard(self, domain: str) -> QueryResult:
        """Check wildcard blocking rules"""
        parts = domain.split('.')
        
        for i in range(len(parts)):
            wildcard = '*.' + '.'.join(parts[i:])
            if wildcard in self.wildcard_rules:
                rule = self.wildcard_rules[wildcard]
                rule.hit_count += 1
                return QueryResult(
                    blocked=True,
                    reason="wildcard_match",
                    block_type=BlockType.WILDCARD,
                    response_ip=self._get_block_response(),
                    matched_rule=wildcard
                )
                
        return QueryResult(blocked=False)
        
    async def _check_regex(self, domain: str) -> QueryResult:
        """Check regex blocking rules"""
        for rule in self.regex_rules:
            if rule.regex_pattern and rule.regex_pattern.match(domain):
                rule.hit_count += 1
                return QueryResult(
                    blocked=True,
                    reason="regex_match",
                    block_type=BlockType.REGEX,
                    response_ip=self._get_block_response(),
                    matched_rule=rule.domain
                )
                
        return QueryResult(blocked=False)
        
    async def _check_parent_domains(self, domain: str) -> QueryResult:
        """Check if any parent domain is blocked"""
        parts = domain.split('.')
        
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.blocklist:
                rule = self.blocklist[parent]
                rule.hit_count += 1
                return QueryResult(
                    blocked=True,
                    reason="parent_domain_blocked",
                    block_type=rule.block_type,
                    response_ip=self._get_block_response(),
                    matched_rule=parent
                )
                
        return QueryResult(blocked=False)
        
    def _get_block_response(self) -> str:
        """Get the IP address to return for blocked queries"""
        if self.block_action == BlockAction.NULL_IP:
            return "0.0.0.0"
        elif self.block_action == BlockAction.NULL_IPV6:
            return "::"
        elif self.block_action == BlockAction.CUSTOM_IP:
            return self.custom_block_ip
        else:
            return "0.0.0.0"
            
    async def add_to_blocklist(self, domain: str, block_type: BlockType = BlockType.EXACT, source: str = "manual"):
        """Add a domain to the blocklist"""
        async with self._lock:
            domain = domain.lower().strip('.')
            
            if block_type == BlockType.WILDCARD:
                if not domain.startswith('*.'):
                    domain = '*.' + domain
                self.wildcard_rules[domain] = BlockRule(
                    domain=domain,
                    block_type=block_type,
                    source=source,
                    added_timestamp=time.time()
                )
            elif block_type == BlockType.REGEX:
                try:
                    compiled = re.compile(domain, re.IGNORECASE)
                    rule = BlockRule(
                        domain=domain,
                        block_type=block_type,
                        source=source,
                        regex_pattern=compiled,
                        added_timestamp=time.time()
                    )
                    self.regex_rules.append(rule)
                except re.error as e:
                    raise ValueError(f"Invalid regex pattern: {e}")
            else:
                self.blocklist[domain] = BlockRule(
                    domain=domain,
                    block_type=block_type,
                    source=source,
                    added_timestamp=time.time()
                )
                
            logger.info(f"Added {domain} to blocklist (type: {block_type.value})")
            
    async def remove_from_blocklist(self, domain: str):
        """Remove a domain from the blocklist"""
        async with self._lock:
            domain = domain.lower().strip('.')
            
            # Try to remove from different lists
            removed = False
            
            if domain in self.blocklist:
                del self.blocklist[domain]
                removed = True
                
            if domain in self.wildcard_rules:
                del self.wildcard_rules[domain]
                removed = True
                
            # Remove from regex rules
            self.regex_rules = [r for r in self.regex_rules if r.domain != domain]
            
            if removed:
                logger.info(f"Removed {domain} from blocklist")
            else:
                logger.warning(f"Domain {domain} not found in blocklist")
                
    async def add_to_whitelist(self, domain: str):
        """Add a domain to the whitelist"""
        async with self._lock:
            domain = domain.lower().strip('.')
            self.whitelist.add(domain)
            logger.info(f"Added {domain} to whitelist")
            
    async def remove_from_whitelist(self, domain: str):
        """Remove a domain from the whitelist"""
        async with self._lock:
            domain = domain.lower().strip('.')
            self.whitelist.discard(domain)
            logger.info(f"Removed {domain} from whitelist")
            
    async def get_statistics(self) -> Dict:
        """Get blocking statistics"""
        stats = self.stats.copy()
        stats['blocklist_size'] = len(self.blocklist)
        stats['whitelist_size'] = len(self.whitelist)
        stats['regex_rules_count'] = len(self.regex_rules)
        stats['wildcard_rules_count'] = len(self.wildcard_rules)
        
        if stats['total_queries'] > 0:
            stats['block_percentage'] = (stats['blocked_queries'] / stats['total_queries']) * 100
        else:
            stats['block_percentage'] = 0
            
        return stats
        
    async def get_top_blocked(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top blocked domains by hit count"""
        all_rules = []
        
        # Collect all rules with hit counts
        for rule in self.blocklist.values():
            if rule.hit_count > 0:
                all_rules.append((rule.domain, rule.hit_count))
                
        for rule in self.wildcard_rules.values():
            if rule.hit_count > 0:
                all_rules.append((rule.domain, rule.hit_count))
                
        for rule in self.regex_rules:
            if rule.hit_count > 0:
                all_rules.append((rule.domain, rule.hit_count))
                
        # Sort by hit count
        all_rules.sort(key=lambda x: x[1], reverse=True)
        
        return all_rules[:limit]
        
    async def reload_lists(self):
        """Reload all blocklists and whitelists"""
        logger.info("Reloading block and whitelists...")
        await self.load_blocklists()
        await self.load_whitelist()
        await self.compile_regex_rules()
        logger.info("Lists reloaded successfully")