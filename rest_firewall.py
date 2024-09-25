from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset

from ryu.app.wsgi import ControllerBase, route, Response
from ryu.lib.packet import ether_types
import json

class BlockHosts(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]    
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }


    def __init__(self, *args, **kwargs):
        super(BlockHosts, self).__init__(*args, **kwargs)
        self.datapaths = {}  
        self.mac_to_port = {}
        self.dpset = kwargs['dpset']
        self.blocked_pairs = set()
        
        wsgi = kwargs['wsgi']
        wsgi.register(BlockingController, {'block_hosts_app': self})
        

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        
        if datapath is None:
            return
        
        if ev.state == MAIN_DISPATCHER:
            print("Switch %s connected" % datapath.id)
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                print("Switch %s disconnected" % datapath.id)
                del self.datapaths[datapath.id]

    def block_pair(self, src_mac, dst_mac):
        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Añadir el par a la lista de bloqueos
            self.blocked_pairs.add((src_mac, dst_mac))
            
            # Crear una coincidencia para bloquear tráfico entre los MACs
            match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            actions = []  # Acciones vacías para bloquear (drop)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, instructions=inst)
            
            datapath.send_msg(mod)

    def unblock_pair(self, src_mac, dst_mac):
        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Verificar si el par de MACs está realmente bloqueado
            if (src_mac, dst_mac) in self.blocked_pairs:
                self.logger.info(f"Desbloqueando tráfico entre {src_mac} y {dst_mac}")
                
                # Remover el par de la lista de bloqueos
                self.blocked_pairs.discard((src_mac, dst_mac))
                
                # Crear una coincidencia para remover el bloqueo
                match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, 
                                        out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                        match=match)
                
                datapath.send_msg(mod)
            else:
                self.logger.info(f"El par {src_mac} -> {dst_mac} no está bloqueado.")

    
    def update_block_rules(self):
        for dp in self.dpset.get_all():
            self.clear_block_rules(dp)
            for src_mac, dst_mac in self.blocked_pairs:
                self.block_hosts(dp, src_mac, dst_mac)

    def clear_block_rules(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(
            datapath=datapath, 
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, 
            out_group=ofproto.OFPG_ANY,
            priority=2,
            match=match
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install the table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        for pair in self.blocked_pairs:
            self.block_hosts(datapath, pair[0], pair[1])
            self.block_hosts(datapath, pair[1], pair[0])

        self.update_block_rules()

        

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def block_hosts(self, datapath, src_mac, dst_mac):
        #ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
        actions = []  # Empty action list to drop the packets
        self.add_flow(datapath, 2, match, actions)  # Higher priority

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packets
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Verify if we're not installing a flow for h1 to h2 or vice versa
            
            for pair in self.blocked_pairs:
                if src == pair[0] and dst == pair[1] or src == pair[1] and dst == pair[0]:
                    print("Blocking traffic between %s and %s" % (src, dst))                
                    self.add_flow(datapath, 1, match, actions)
                
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    


class BlockingController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(BlockingController, self).__init__(req, link, data, **config)
        self.block_hosts_app = data['block_hosts_app']

    @route('block', '/block', methods=['POST'])
    def block_hosts_handler(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode('utf-8'))
            mac1 = body['mac1']
            mac2 = body['mac2']
            self.block_hosts_app.block_pair(mac1, mac2)
            return Response(content_type='application/json', body=json.dumps({'status': 'success'}))
        except Exception as e:
            return Response(status=400, body=str(e))

    @route('unblock', '/unblock', methods=['POST'])
    def unblock_hosts_handler(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode('utf-8'))
            mac1 = body['mac1']
            mac2 = body['mac2']
            self.block_hosts_app.unblock_pair(mac1, mac2)
            return Response(content_type='application/json', body=json.dumps({'status': 'success'}))
        except Exception as e:
            return Response(status=400, body=str(e))
