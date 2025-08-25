# Create the flow manager for handling SDN flow rules
flow_manager_content = '''"""
Flow Manager for SDN DDoS Protection System
Handles installation, modification, and removal of OpenFlow rules for attack mitigation
"""

import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict

from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp

from utils.logger import controller_logger
from utils.config import CONFIG

@dataclass
class FlowRule:
    """Represents an OpenFlow rule"""
    match: Dict[str, Any]
    actions: List[Any]
    priority: int
    idle_timeout: int
    hard_timeout: int
    cookie: int
    table_id: int = 0
    flags: int = 0

@dataclass
class MitigationRule:
    """Represents a mitigation rule with metadata"""
    flow_rule: FlowRule
    rule_type: str
    target: str
    installed_at: float
    expires_at: float
    attack_info: Dict[str, Any]

class FlowManager:
    """
    Manages OpenFlow rules for traffic control and DDoS mitigation
    """
    
    def __init__(self, controller):
        self.controller = controller
        
        # Rule tracking
        self.active_rules = defaultdict(list)  # dpid -> [MitigationRule]
        self.rule_counter = 0
        
        # Priority ranges for different rule types
        self.priorities = {
            'drop': 3000,
            'rate_limit': 2000,
            'redirect': 1500,
            'monitor': 1000,
            'default': 0
        }
        
        # Timeout settings
        self.timeouts = {
            'attack_mitigation': CONFIG.detection.mitigation_timeout,
            'temporary_block': 60,
            'rate_limit': 300,
            'monitoring': 0  # No timeout for monitoring rules
        }
        
        controller_logger.info("Flow Manager initialized")
    
    def add_flow(self, datapath, priority: int, match, actions: List, 
                 idle_timeout: int = 0, hard_timeout: int = 0,
                 table_id: int = 0, cookie: int = 0):
        """Add a flow rule to a switch"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Create flow mod message
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                cookie=cookie,
                cookie_mask=0,
                table_id=table_id,
                command=ofproto.OFPFC_ADD,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                priority=priority,
                buffer_id=ofproto.OFP_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0,
                match=match,
                instructions=inst
            )
            
            datapath.send_msg(flow_mod)
            
            controller_logger.debug(
                f"Flow added to switch {datapath.id}: priority={priority}, "
                f"match={match}, timeout={hard_timeout}"
            )
            
        except Exception as e:
            controller_logger.error(f"Error adding flow to switch {datapath.id}: {e}")
    
    def remove_flow(self, datapath, match, priority: int = 0, table_id: int = 0):
        """Remove a flow rule from a switch"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
                priority=priority,
                table_id=table_id
            )
            
            datapath.send_msg(flow_mod)
            
            controller_logger.debug(f"Flow removed from switch {datapath.id}")
            
        except Exception as e:
            controller_logger.error(f"Error removing flow from switch {datapath.id}: {e}")
    
    def install_mitigation_rules(self, datapath, attack_info: Dict[str, Any]):
        """
        Install mitigation rules based on detected attack
        
        Args:
            datapath: OpenFlow datapath (switch)
            attack_info: Information about the detected attack
        """
        try:
            attack_type = attack_info.get('type', 'unknown')
            source_ip = attack_info.get('source_ip')
            target_ip = attack_info.get('target_ip')
            
            controller_logger.info(
                f"Installing mitigation rules for {attack_type} attack on switch {datapath.id}"
            )
            
            # Install rules based on attack type
            if attack_type == 'syn_flood':
                self._install_syn_flood_mitigation(datapath, attack_info)
            elif attack_type == 'udp_flood':
                self._install_udp_flood_mitigation(datapath, attack_info)
            elif attack_type == 'icmp_flood':
                self._install_icmp_flood_mitigation(datapath, attack_info)
            elif attack_type == 'port_scan':
                self._install_port_scan_mitigation(datapath, attack_info)
            else:
                # Generic volumetric attack mitigation
                self._install_generic_mitigation(datapath, attack_info)
            
            # Install general rate limiting if needed
            if attack_info.get('severity') == 'high':
                self._install_rate_limiting(datapath, attack_info)
            
            controller_logger.info(f"Mitigation rules installed on switch {datapath.id}")
            
        except Exception as e:
            controller_logger.error(f"Error installing mitigation rules: {e}")
    
    def _install_syn_flood_mitigation(self, datapath, attack_info: Dict[str, Any]):
        """Install SYN flood specific mitigation rules"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        source_ip = attack_info.get('source_ip')
        target_ip = attack_info.get('target_ip')
        
        # Block SYN packets from attack source
        if source_ip:
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=source_ip,
                ip_proto=6,  # TCP
                tcp_flags=0x02  # SYN flag
            )
            actions = []  # Drop action (empty actions list)
            
            rule = MitigationRule(
                flow_rule=FlowRule(
                    match=match,
                    actions=actions,
                    priority=self.priorities['drop'],
                    idle_timeout=0,
                    hard_timeout=self.timeouts['attack_mitigation'],
                    cookie=self._generate_cookie()
                ),
                rule_type='syn_flood_block',
                target=source_ip,
                installed_at=time.time(),
                expires_at=time.time() + self.timeouts['attack_mitigation'],
                attack_info=attack_info
            )
            
            self._install_mitigation_rule(datapath, rule)
        
        # Rate limit SYN packets to target
        if target_ip:
            self._install_syn_rate_limit(datapath, target_ip, attack_info)
    
    def _install_udp_flood_mitigation(self, datapath, attack_info: Dict[str, Any]):
        """Install UDP flood specific mitigation rules"""
        parser = datapath.ofproto_parser
        source_ip = attack_info.get('source_ip')
        
        if source_ip:
            # Block all UDP traffic from source
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=source_ip,
                ip_proto=17  # UDP
            )
            actions = []  # Drop
            
            rule = MitigationRule(
                flow_rule=FlowRule(
                    match=match,
                    actions=actions,
                    priority=self.priorities['drop'],
                    idle_timeout=0,
                    hard_timeout=self.timeouts['attack_mitigation'],
                    cookie=self._generate_cookie()
                ),
                rule_type='udp_flood_block',
                target=source_ip,
                installed_at=time.time(),
                expires_at=time.time() + self.timeouts['attack_mitigation'],
                attack_info=attack_info
            )
            
            self._install_mitigation_rule(datapath, rule)
    
    def _install_icmp_flood_mitigation(self, datapath, attack_info: Dict[str, Any]):
        """Install ICMP flood specific mitigation rules"""
        parser = datapath.ofproto_parser
        source_ip = attack_info.get('source_ip')
        
        if source_ip:
            # Block all ICMP traffic from source
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=source_ip,
                ip_proto=1  # ICMP
            )
            actions = []  # Drop
            
            rule = MitigationRule(
                flow_rule=FlowRule(
                    match=match,
                    actions=actions,
                    priority=self.priorities['drop'],
                    idle_timeout=0,
                    hard_timeout=self.timeouts['attack_mitigation'],
                    cookie=self._generate_cookie()
                ),
                rule_type='icmp_flood_block',
                target=source_ip,
                installed_at=time.time(),
                expires_at=time.time() + self.timeouts['attack_mitigation'],
                attack_info=attack_info
            )
            
            self._install_mitigation_rule(datapath, rule)
    
    def _install_port_scan_mitigation(self, datapath, attack_info: Dict[str, Any]):
        """Install port scanning specific mitigation rules"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        source_ip = attack_info.get('source_ip')
        
        if source_ip:
            # Rate limit all traffic from scanner
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=source_ip
            )
            
            # Redirect to controller for rate limiting (simplified approach)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 64)]
            
            rule = MitigationRule(
                flow_rule=FlowRule(
                    match=match,
                    actions=actions,
                    priority=self.priorities['rate_limit'],
                    idle_timeout=0,
                    hard_timeout=self.timeouts['attack_mitigation'],
                    cookie=self._generate_cookie()
                ),
                rule_type='port_scan_limit',
                target=source_ip,
                installed_at=time.time(),
                expires_at=time.time() + self.timeouts['attack_mitigation'],
                attack_info=attack_info
            )
            
            self._install_mitigation_rule(datapath, rule)
    
    def _install_generic_mitigation(self, datapath, attack_info: Dict[str, Any]):
        """Install generic mitigation rules for volumetric attacks"""
        parser = datapath.ofproto_parser
        source_ip = attack_info.get('source_ip')
        
        if source_ip:
            # Block all traffic from source IP
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=source_ip
            )
            actions = []  # Drop
            
            rule = MitigationRule(
                flow_rule=FlowRule(
                    match=match,
                    actions=actions,
                    priority=self.priorities['drop'],
                    idle_timeout=0,
                    hard_timeout=self.timeouts['attack_mitigation'],
                    cookie=self._generate_cookie()
                ),
                rule_type='generic_block',
                target=source_ip,
                installed_at=time.time(),
                expires_at=time.time() + self.timeouts['attack_mitigation'],
                attack_info=attack_info
            )
            
            self._install_mitigation_rule(datapath, rule)
    
    def _install_rate_limiting(self, datapath, attack_info: Dict[str, Any]):
        """Install rate limiting rules for high-severity attacks"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        target_ip = attack_info.get('target_ip')
        
        if target_ip:
            # Rate limit traffic to target (simplified - redirect to controller)
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_dst=target_ip
            )
            
            # Send to controller for rate limiting decision
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                            ofproto.OFPCML_NO_BUFFER)]
            
            rule = MitigationRule(
                flow_rule=FlowRule(
                    match=match,
                    actions=actions,
                    priority=self.priorities['rate_limit'],
                    idle_timeout=0,
                    hard_timeout=self.timeouts['rate_limit'],
                    cookie=self._generate_cookie()
                ),
                rule_type='rate_limit',
                target=target_ip,
                installed_at=time.time(),
                expires_at=time.time() + self.timeouts['rate_limit'],
                attack_info=attack_info
            )
            
            self._install_mitigation_rule(datapath, rule)
    
    def _install_syn_rate_limit(self, datapath, target_ip: str, attack_info: Dict[str, Any]):
        """Install SYN rate limiting to protect target"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Rate limit SYN packets to target
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_dst=target_ip,
            ip_proto=6,  # TCP
            tcp_flags=0x02  # SYN flag
        )
        
        # Send to controller for SYN rate limiting
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 64)]
        
        rule = MitigationRule(
            flow_rule=FlowRule(
                match=match,
                actions=actions,
                priority=self.priorities['rate_limit'],
                idle_timeout=0,
                hard_timeout=self.timeouts['rate_limit'],
                cookie=self._generate_cookie()
            ),
            rule_type='syn_rate_limit',
            target=target_ip,
            installed_at=time.time(),
            expires_at=time.time() + self.timeouts['rate_limit'],
            attack_info=attack_info
        )
        
        self._install_mitigation_rule(datapath, rule)
    
    def _install_mitigation_rule(self, datapath, rule: MitigationRule):
        """Install a mitigation rule on the switch"""
        try:
            # Install the actual flow rule
            self.add_flow(
                datapath=datapath,
                priority=rule.flow_rule.priority,
                match=rule.flow_rule.match,
                actions=rule.flow_rule.actions,
                idle_timeout=rule.flow_rule.idle_timeout,
                hard_timeout=rule.flow_rule.hard_timeout,
                cookie=rule.flow_rule.cookie
            )
            
            # Track the rule
            self.active_rules[datapath.id].append(rule)
            
            controller_logger.info(
                f"Mitigation rule installed: {rule.rule_type} targeting {rule.target}"
            )
            
        except Exception as e:
            controller_logger.error(f"Error installing mitigation rule: {e}")
    
    def remove_mitigation_rules(self, datapath):
        """Remove all mitigation rules from a switch"""
        try:
            dpid = datapath.id
            rules_to_remove = self.active_rules.get(dpid, [])
            
            for rule in rules_to_remove:
                try:
                    self.remove_flow(
                        datapath=datapath,
                        match=rule.flow_rule.match,
                        priority=rule.flow_rule.priority
                    )
                except Exception as e:
                    controller_logger.warning(f"Error removing rule: {e}")
            
            # Clear tracked rules
            self.active_rules[dpid] = []
            
            controller_logger.info(f"Mitigation rules removed from switch {dpid}")
            
        except Exception as e:
            controller_logger.error(f"Error removing mitigation rules: {e}")
    
    def cleanup_expired_rules(self):
        """Remove expired mitigation rules"""
        current_time = time.time()
        
        for dpid, rules in self.active_rules.items():
            expired_rules = [rule for rule in rules if rule.expires_at <= current_time]
            
            if expired_rules:
                datapath = self.controller.datapaths.get(dpid)
                if datapath:
                    for rule in expired_rules:
                        try:
                            self.remove_flow(
                                datapath=datapath,
                                match=rule.flow_rule.match,
                                priority=rule.flow_rule.priority
                            )
                            rules.remove(rule)
                            controller_logger.info(f"Expired rule removed: {rule.rule_type}")
                        except Exception as e:
                            controller_logger.warning(f"Error removing expired rule: {e}")
    
    def install_monitoring_rules(self, datapath):
        """Install monitoring rules for traffic analysis"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Monitor all traffic (send sample to controller)
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_NORMAL),  # Forward normally
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 128)  # Send sample to controller
        ]
        
        self.add_flow(
            datapath=datapath,
            priority=self.priorities['monitor'],
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0,  # Permanent rule
            cookie=self._generate_cookie()
        )
        
        controller_logger.info(f"Monitoring rules installed on switch {datapath.id}")
    
    def block_ip_address(self, datapath, ip_address: str, duration: int = None):
        """Manually block an IP address"""
        parser = datapath.ofproto_parser
        
        if duration is None:
            duration = self.timeouts['temporary_block']
        
        # Block all traffic from IP
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=ip_address
        )
        actions = []  # Drop
        
        rule = MitigationRule(
            flow_rule=FlowRule(
                match=match,
                actions=actions,
                priority=self.priorities['drop'],
                idle_timeout=0,
                hard_timeout=duration,
                cookie=self._generate_cookie()
            ),
            rule_type='manual_block',
            target=ip_address,
            installed_at=time.time(),
            expires_at=time.time() + duration,
            attack_info={'type': 'manual_block', 'source_ip': ip_address}
        )
        
        self._install_mitigation_rule(datapath, rule)
        
        controller_logger.info(f"IP {ip_address} blocked manually for {duration} seconds")
    
    def unblock_ip_address(self, datapath, ip_address: str):
        """Manually unblock an IP address"""
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=ip_address
        )
        
        self.remove_flow(datapath, match, self.priorities['drop'])
        
        # Remove from active rules
        dpid = datapath.id
        self.active_rules[dpid] = [
            rule for rule in self.active_rules[dpid] 
            if rule.target != ip_address
        ]
        
        controller_logger.info(f"IP {ip_address} unblocked manually")
    
    def _generate_cookie(self) -> int:
        """Generate unique cookie for flow rules"""
        self.rule_counter += 1
        return self.rule_counter
    
    def get_active_rules(self, dpid: Optional[int] = None) -> Dict[str, List[Dict]]:
        """Get information about active mitigation rules"""
        if dpid:
            rules = self.active_rules.get(dpid, [])
        else:
            rules = []
            for switch_rules in self.active_rules.values():
                rules.extend(switch_rules)
        
        return [
            {
                'rule_type': rule.rule_type,
                'target': rule.target,
                'installed_at': rule.installed_at,
                'expires_at': rule.expires_at,
                'priority': rule.flow_rule.priority,
                'remaining_time': max(0, rule.expires_at - time.time())
            }
            for rule in rules
        ]
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get statistics about mitigation rules"""
        total_rules = sum(len(rules) for rules in self.active_rules.values())
        
        rule_types = defaultdict(int)
        for rules in self.active_rules.values():
            for rule in rules:
                rule_types[rule.rule_type] += 1
        
        return {
            'total_active_rules': total_rules,
            'switches_with_rules': len([dpid for dpid, rules in self.active_rules.items() if rules]),
            'rule_types': dict(rule_types),
            'rule_counter': self.rule_counter
        }
'''

with open('sdn_ddos_protection/controller/flow_manager.py', 'w') as f:
    f.write(flow_manager_content)

print("Flow Manager created successfully!")