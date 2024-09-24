import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4

class SimpleLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleLoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.virtual_ip = '10.0.0.100'
        self.virtual_mac = '00:00:00:00:00:10'
        self.server_ips = ['10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.server_macs = ['00:00:00:00:00:02', '00:00:00:00:00:03', '00:00:00:00:00:04']
        self.server_loads = {ip: 0 for ip in self.server_ips}  # Initialize server loads
        
                

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initialize mac_to_port for this datapath
        self.mac_to_port[datapath.id] = {}

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Learn the MAC address to avoid flooding next time
        self.mac_to_port[datapath.id][eth.src] = in_port

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, pkt, eth, in_port)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip.dst == self.virtual_ip:
                server_ip, server_mac = self.choose_server()
                self.server_loads[server_ip] += 1  # Increment load on chosen server
                self.forward_packet(datapath, msg, in_port, server_ip, server_mac)
                print(f"Reenviando paquete - Puerto de entrada: {in_port}, Dirección IP del servidor: {server_ip}, Dirección MAC del servidor: {server_mac}")
            else:
                self.forward_packet(datapath, msg, in_port, ip.dst, eth.dst)
                print(f"Reenviando paquete - Puerto de entrada: {in_port}, Dirección IP de destino: {ip.dst}, Dirección MAC de destino: {eth.dst}")

    def handle_arp(self, datapath, pkt, eth, in_port):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.virtual_ip:
            self.send_arp_reply(datapath, arp_pkt, eth, in_port)
        else:
            self.flood_packet(datapath, pkt, in_port)

    def send_arp_reply(self, datapath, arp_request, eth, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype,
            dst=eth.src,
            src=self.virtual_mac))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.virtual_mac,
            src_ip=arp_request.dst_ip,
            dst_mac=arp_request.src_mac,
            dst_ip=arp_request.src_ip))

        self.send_packet(datapath, arp_reply, in_port)

    def send_packet(self, datapath, pkt, port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    def flood_packet(self, datapath, pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        pkt.serialize()
        data = pkt.data
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def choose_server(self):
        # Find the server with the least load
        min_load_server = min(self.server_loads, key=self.server_loads.get)
        min_load_index = self.server_ips.index(min_load_server)
        return self.server_ips[min_load_index], self.server_macs[min_load_index]

    def forward_packet(self, datapath, msg, in_port, dst_ip, dst_mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionSetField(ipv4_dst=dst_ip),
            parser.OFPActionOutput(self.mac_to_port[datapath.id][dst_mac])
        ]

        # Send the packet out
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)
