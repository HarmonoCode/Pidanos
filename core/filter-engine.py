"""
Filter Engine Module
~~~~~~~~~~~~~~~~~~~~

Advanced filtering engine for DNS queries with multiple filter types.
"""

import re
import logging
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Pattern
from dataclasses import dataclass
from enum import Enum, auto
from ipaddress import ip_network, ip_address
import tldextract

logger = logging.getLogger(__name__)


class FilterType(Enum):
    """Types of filters available"""
    DOMAIN_EXACT = auto()
    DOMAIN_WILDCARD = auto()
    DOMAIN_REGEX = auto()
    IP_ADDRESS = auto()
    IP_NETWORK = auto()
    TLD = auto()
    CNAME_CLOAKING = auto()
    PARENTAL = auto()
    MALWARE = auto()
    CUSTOM = auto()


class FilterAction(Enum):
    """Actions to take when filter matches"""
    BLOCK = "block"
    ALLOW = "allow"
    REDIRECT = "redirect"
    LOG_ONLY = "log_only"


@dataclass
class FilterRule:
    """Represents a single filter rule"""
    pattern: str
    filter_type: FilterType
    action: FilterAction
    priority: int = 50
    description: Optional[str] = None
    compiled_pattern: Optional[Pattern] = None
    redirect_to: Optional[str] = None
    tags: List[str] = None
    enabled: bool = True
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class FilterEngine:
    """Advanced filtering engine for DNS queries"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.filters: Dict[FilterType, List[FilterRule]] = {ft: [] for ft in FilterType}
        self.tld_extractor = tldextract.TLDExtract(cache_dir=None)
        self._lock = asyncio.Lock()
        self._filter_stats = {ft: {'matched': 0, 'processed': 0} for ft in FilterType}
        self.cname_cache: Dict[str, str] = {}
        
    async def initialize(self):
        """Initialize the filter engine"""
        logger.info("Initializing Filter Engine...")
        
        # Load default filters
        await self._load_default_filters()
        
        # Compile regex patterns
        await self._compile_patterns()
        
        logger.info(f"Filter Engine initialized with {self._count_total_filters()} filters")
        
    async def _load_default_filters(self):
        """Load default filter rules"""
        # TLD filters
        blocked_tlds = [".tk", ".ml", ".ga", ".cf"]
        for tld in blocked_tlds:
            await self.add_filter(
                pattern=tld,
                filter_type=FilterType.TLD,
                action=FilterAction.BLOCK,
                description=f"Block {tld} TLD",
                tags=["suspicious_tld"]
            )
            
        # Common tracking domains regex
        tracking_patterns = [
            r"^(www\.)?google-analytics\.com$",
            r"^(www\.)?googletagmanager\.com$",
            r"^(www\.)?facebook\.com/tr",
            r"^pixel\.facebook\.com$",
            r"^analytics\.(.*\.)?twitter\.com$",
            r"^(.*\.)?doubleclick\.net$",
            r"^(.*\.)?googlesyndication\.com$",
            r"^(.*\.)?googleadservices\.com$",
            r"^(.*\.)?amazon-adsystem\.com$",
            r"^(.*\.)?scorecardresearch\.com$"
        ]
        
        for pattern in tracking_patterns:
            await self.add_filter(
                pattern=pattern,
                filter_type=FilterType.DOMAIN_REGEX,
                action=FilterAction.BLOCK,
                description="Block tracking domain",
                tags=["tracking", "privacy"]
            )
            
        # Parental control patterns
        parental_keywords = ["porn", "xxx", "adult", "sex"]
        for keyword in parental_keywords:
            await self.add_filter(
                pattern=f".*{keyword}.*",
                filter_type=FilterType.DOMAIN_REGEX,
                action=FilterAction.BLOCK,
                description=f"Parental control: {keyword}",
                tags=["parental", "adult_content"],
                enabled=False  # Disabled by default
            )
            
        # Private IP ranges to block DNS rebinding
        private_networks = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "fc00::/7",
            "fe80::/10"
        ]
        
        for network in private_networks:
            await self.add_filter(
                pattern=network,
                filter_type=FilterType.IP_NETWORK,
                action=FilterAction.BLOCK,
                description=f"Block private network {network}",
                tags=["security", "dns_rebinding"]
            )
            
    async def _compile_patterns(self):
        """Compile regex patterns for efficiency"""
        async with self._lock:
            for rule in self.filters[FilterType.DOMAIN_REGEX]:
                if rule.enabled and not rule.compiled_pattern:
                    try:
                        rule.compiled_pattern = re.compile(rule.pattern, re.IGNORECASE)
                    except re.error as e:
                        logger.error(f"Failed to compile regex {rule.pattern}: {e}")
                        rule.enabled = False
                        
    def _count_total_filters(self) -> int:
        """Count total number of active filters"""
        return sum(len([r for r in rules if r.enabled]) for rules in self.filters.values())
        
    async def add_filter(self, pattern: str, filter_type: FilterType, 
                        action: FilterAction, **kwargs) -> FilterRule:
        """Add a new filter rule"""
        rule = FilterRule(
            pattern=pattern,
            filter_type=filter_type,
            action=action,
            **kwargs
        )
        
        async with self._lock:
            self.filters[filter_type].append(rule)
            
            # Compile regex if needed
            if filter_type == FilterType.DOMAIN_REGEX and rule.enabled:
                try:
                    rule.compiled_pattern = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logger.error(f"Failed to compile regex {pattern}: {e}")
                    rule.enabled = False
                    
        logger.debug(f"Added {filter_type.name} filter: {pattern}")
        return rule
        
    async def remove_filter(self, pattern: str, filter_type: FilterType) -> bool:
        """Remove a filter rule"""
        async with self._lock:
            original_count = len(self.filters[filter_type])
            self.filters[filter_type] = [
                r for r in self.filters[filter_type] 
                if r.pattern != pattern
            ]
            removed = len(self.filters[filter_type]) < original_count
            
        if removed:
            logger.debug(f"Removed {filter_type.name} filter: {pattern}")
            
        return removed
        
    async def check_domain(self, domain: str, client_ip: Optional[str] = None) -> Tuple[FilterAction, Optional[FilterRule]]:
        """
        Check domain against all filters
        
        Returns:
            Tuple of (action, matching_rule)
        """
        domain = domain.lower().strip('.')
        
        # Extract domain parts
        extracted = self.tld_extractor(domain)
        
        # Check filters in priority order
        filters_to_check = [
            (FilterType.DOMAIN_EXACT, self._check_exact_domain),
            (FilterType.DOMAIN_WILDCARD, self._check_wildcard_domain),
            (FilterType.DOMAIN_REGEX, self._check_regex_domain),
            (FilterType.TLD, self._check_tld),
            (FilterType.PARENTAL, self._check_parental),
            (FilterType.MALWARE, self._check_malware),
            (FilterType.CUSTOM, self._check_custom)
        ]
        
        # Track which action to take (allow by default)
        final_action = FilterAction.ALLOW
        final_rule = None
        highest_priority = -1
        
        for filter_type, check_func in filters_to_check:
            self._filter_stats[filter_type]['processed'] += 1
            
            action, rule = await check_func(domain, extracted)
            
            if rule and rule.enabled and rule.priority > highest_priority:
                final_action = action
                final_rule = rule
                highest_priority = rule.priority
                self._filter_stats[filter_type]['matched'] += 1
                
                # If we have a high priority block, no need to check further
                if action == FilterAction.BLOCK and rule.priority >= 90:
                    break
                    
        return final_action, final_rule
        
    async def check_ip(self, ip_str: str) -> Tuple[FilterAction, Optional[FilterRule]]:
        """Check IP address against filters"""
        try:
            ip = ip_address(ip_str)
        except ValueError:
            return FilterAction.ALLOW, None
            
        # Check IP address filters
        for rule in self.filters[FilterType.IP_ADDRESS]:
            if rule.enabled and rule.pattern == ip_str:
                return rule.action, rule
                
        # Check IP network filters
        for rule in self.filters[FilterType.IP_NETWORK]:
            if rule.enabled:
                try:
                    network = ip_network(rule.pattern)
                    if ip in network:
                        return rule.action, rule
                except ValueError:
                    logger.error(f"Invalid IP network pattern: {rule.pattern}")
                    
        return FilterAction.ALLOW, None
        
    async def _check_exact_domain(self, domain: str, extracted) -> Tuple[FilterAction, Optional[FilterRule]]:
        """Check exact domain match"""
        for rule in self.filters[FilterType.DOMAIN_EXACT]:
            if rule.enabled and rule.pattern == domain:
                return rule.action, rule
        return FilterAction.ALLOW, None
        
    async def _check_wildcard_domain(self, domain: str, extracted) -> Tuple[FilterAction, Optional[FilterRule]]:
        """Check wildcard domain match"""
        for rule in self.filters[FilterType.DOMAIN_WILDCARD]:
            if not rule.enabled:
                continue
                
            pattern = rule.pattern
            
            # Handle *.example.com pattern
            if pattern.startswith('*.'):
                base_pattern = pattern[2:]
                if domain.endswith(base_pattern) or domain == base_pattern[1:]:
                    return rule.action, rule
                    
            # Handle example.* pattern
            elif pattern.endswith('.*'):
                base_pattern = pattern[:-2]
                if domain.startswith(base_pattern):
                    return rule.action, rule
                    
        return FilterAction.ALLOW, None
        
    async def _check_regex_domain(self, domain: str, extracted) -> Tuple[FilterAction, Optional[FilterRule]]:
        """Check regex domain match"""
        for rule in self.filters[FilterType.DOMAIN_REGEX]:
            if rule.enabled and rule.compiled_pattern:
                if rule.compiled_pattern.match(domain):
                    return rule.action, rule
        return FilterAction.ALLOW, None
        
    async def _check_tld(self, domain: str, extracted) -> Tuple[FilterAction, Optional[FilterRule]]:
        """Check TLD filters"""
        if extracted.suffix:
            tld = '.' + extracted.suffix
            for rule in self.filters[FilterType.TLD]:
                if rule.enabled and rule.pattern == tld:
                    return rule.action, rule
        return FilterAction.ALLOW, None
        
    async def _check_parental(self, domain: str, extracted) -> Tuple[FilterAction, Optional[FilterRule]]:
        """Check parental control filters"""
        # Use regex filters tagged as parental
        for rule in self.filters[FilterType.DOMAIN_REGEX]:
            if rule.enabled and 'parental' in rule.tags:
                if rule.compiled_pattern and rule.compiled_pattern.search(domain):
                    return rule.action, rule
        return FilterAction.ALLOW, None
        
    async def _check_malware(self, domain: str, extracted) -> Tuple[FilterAction, Optional[FilterRule]]:
        """Check malware filters"""
        # This would check against malware databases
        # For now, return allow
        return FilterAction.ALLOW, None
        
    async def _check_custom(self, domain: str, extracted) -> Tuple[FilterAction, Optional[FilterRule]]:
        """Check custom filters"""
        for rule in self.filters[FilterType.CUSTOM]:
            if rule.enabled:
                # Custom filter logic would go here
                pass
        return FilterAction.ALLOW, None
        
    async def check_cname_cloaking(self, domain: str, cname_chain: List[str]) -> Tuple[FilterAction, Optional[FilterRule]]:
        """
        Check for CNAME cloaking
        
        Args:
            domain: Original queried domain
            cname_chain: List of CNAMEs in the resolution chain
            
        Returns:
            Action and matching rule if found
        """
        # Store CNAME chain for analysis
        self.cname_cache[domain] = cname_chain[-1] if cname_chain else domain
        
        # Check if any CNAME in the chain should be blocked
        for cname in cname_chain:
            action, rule = await self.check_domain(cname)
            if action == FilterAction.BLOCK:
                logger.info(f"CNAME cloaking detected: {domain} -> {cname}")
                return action, rule
                
        return FilterAction.ALLOW, None
        
    async def get_filter_stats(self) -> Dict:
        """Get filter statistics"""
        stats = {
            'total_filters': self._count_total_filters(),
            'filters_by_type': {},
            'match_stats': {}
        }
        
        for filter_type in FilterType:
            enabled_count = len([r for r in self.filters[filter_type] if r.enabled])
            stats['filters_by_type'][filter_type.name] = {
                'total': len(self.filters[filter_type]),
                'enabled': enabled_count
            }
            
            if filter_type in self._filter_stats:
                stats['match_stats'][filter_type.name] = self._filter_stats[filter_type].copy()
                
        return stats
        
    async def export_filters(self, filepath: str):
        """Export filters to file"""
        filters_data = []
        
        async with self._lock:
            for filter_type, rules in self.filters.items():
                for rule in rules:
                    filters_data.append({
                        'pattern': rule.pattern,
                        'type': filter_type.name,
                        'action': rule.action.value,
                        'priority': rule.priority,
                        'description': rule.description,
                        'tags': rule.tags,
                        'enabled': rule.enabled,
                        'redirect_to': rule.redirect_to
                    })
                    
        try:
            import json
            with open(filepath, 'w') as f:
                json.dump(filters_data, f, indent=2)
            logger.info(f"Exported {len(filters_data)} filters to {filepath}")
        except Exception as e:
            logger.error(f"Failed to export filters: {e}")
            
    async def import_filters(self, filepath: str):
        """Import filters from file"""
        try:
            import json
            with open(filepath, 'r') as f:
                filters_data = json.load(f)
                
            imported = 0
            for filter_dict in filters_data:
                try:
                    filter_type = FilterType[filter_dict['type']]
                    action = FilterAction(filter_dict['action'])
                    
                    await self.add_filter(
                        pattern=filter_dict['pattern'],
                        filter_type=filter_type,
                        action=action,
                        priority=filter_dict.get('priority', 50),
                        description=filter_dict.get('description'),
                        tags=filter_dict.get('tags', []),
                        enabled=filter_dict.get('enabled', True),
                        redirect_to=filter_dict.get('redirect_to')
                    )
                    imported += 1
                except Exception as e:
                    logger.error(f"Failed to import filter {filter_dict}: {e}")
                    
            logger.info(f"Imported {imported} filters from {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to import filters: {e}")
            
    async def enable_filter_group(self, tag: str):
        """Enable all filters with a specific tag"""
        count = 0
        async with self._lock:
            for rules in self.filters.values():
                for rule in rules:
                    if tag in rule.tags and not rule.enabled:
                        rule.enabled = True
                        count += 1
                        
        logger.info(f"Enabled {count} filters with tag '{tag}'")
        return count
        
    async def disable_filter_group(self, tag: str):
        """Disable all filters with a specific tag"""
        count = 0
        async with self._lock:
            for rules in self.filters.values():
                for rule in rules:
                    if tag in rule.tags and rule.enabled:
                        rule.enabled = False
                        count += 1
                        
        logger.info(f"Disabled {count} filters with tag '{tag}'")
        return count