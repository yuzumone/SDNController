# -*- coding: utf-8 -*-
import json
import socket
from operator import attrgetter, itemgetter

from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.app.wsgi import route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.ofproto import ofproto_v1_3
from webob import Response

switch_instance = 'switch_instance'
gateway = ''


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)
        # mac address dictionary
        self.mac_to_port = {}
        # dpid dictionary
        self.datapaths = {}
        # cooperated device dictionary
        self.cooperated = {}
        # stream dictionary
        self.stream = {}
        # Thread
        self.monitor_thread = hub.spawn(self._monitor)
        # REST
        wsgi = kwargs['wsgi']
        wsgi.register(RESTController, {switch_instance: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.add_table_miss(datapath)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, table_id=0)
        datapath.send_msg(mod)

    def add_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst, table_id=0)
        datapath.send_msg(mod)

    def add_flow_from_cooperated(self, datapath, port_no):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=port_no)
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 1, match, actions)

    def add_tcp_flow(self, datapath, port_no, mac, src_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=1, ip_proto=socket.IPPROTO_TCP, tcp_src=src_port,
                                eth_type=0x0800, eth_dst=gateway)
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionSetField(eth_dst=mac),
                   parser.OFPActionOutput(port_no, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 2, match, actions)

    def add_udp_flow(self, datapath, port_no, mac, src_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=1, ip_proto=socket.IPPROTO_UDP, udp_src=src_port,
                                eth_type=0x0800, eth_dst=gateway)
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionSetField(eth_dst=mac),
                   parser.OFPActionOutput(port_no, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 2, match, actions)

    def add_cooperated_device(self, port_no, mac, datapath_id):
        dpid = int(datapath_id, 16)
        port = int(port_no)
        if dpid in self.datapaths:
            print str(dpid) + str(mac) + str(port)
            datapath = self.datapaths[dpid]
            self.add_flow_from_cooperated(datapath, port)
            self.cooperated.setdefault(dpid, {})
            self.cooperated[dpid][port] = mac
            self.stream.setdefault(dpid, {})
            self.stream[dpid][port] = []
            print self.cooperated
            print self.stream
        else:
            print 'error'

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        t = pkt.get_protocols(tcp.tcp)
        u = pkt.get_protocols(udp.udp)

        if t[0:] and self.stream.get(dpid) is not None:
            t_packet = t[0]
            tcp_port = t_packet.src_port
            stream = self.stream[dpid]
            out_port = sorted(stream.items(), key=itemgetter(1))[0][0]
            hw_addr = self.cooperated[datapath.id][out_port]
            self.logger.info("tcp packet port_no: %s out_port: %s hw_addr %s", tcp_port, out_port, hw_addr)
            self.add_tcp_flow(datapath, out_port, hw_addr, tcp_port)
        elif u[0:] and self.stream.get(dpid) is not None:
            u_packet = u[0]
            udp_port = u_packet.src_port
            if udp_port != 5353:
                stream = self.stream[dpid]
                out_port = sorted(stream.items(), key=itemgetter(1))[0][0]
                hw_addr = self.cooperated[datapath.id][out_port]
                self.logger.info("udp packet port_no: %s out_port: %s hw_addr %s", udp_port, out_port, hw_addr)
                self.add_udp_flow(datapath, out_port, hw_addr, udp_port)
        else:
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD and out_port != ofproto.OFPP_LOCAL:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        for stat in sorted([flow for flow in body if flow.priority == 2],
                           key=lambda flow: (flow.match['in_port'])):
            if len(stat.instructions) != 0:
                port_no = stat.instructions[0].actions[1].port
                ip_proto = stat.match['ip_proto']
                if ip_proto == socket.IPPROTO_TCP:
                    tp_src = stat.match['tcp_src']
                elif ip_proto == socket.IPPROTO_UDP:
                    tp_src = stat.match['udp_src']
                self.logger.info('port_no: %s src_port: %s', port_no, tp_src)
                ports = self.stream[dpid][port_no]
                if tp_src not in ports:
                    ports.append(tp_src)
                    self.stream[dpid][port_no] = ports

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        stat_list = []

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            stat_list.append(stat.port_no)
        if len(self.stream) != 0:
            keys = self.stream[dpid].keys()
            del_list = list(filter(lambda x: x not in stat_list, keys))
            if len(del_list) != 0:
                print del_list
                for port in del_list:
                    mod = parser.OFPFlowMod(datapath=datapath, out_port=port,
                                            out_group=ofproto.OFPG_ANY, command=ofproto.OFPFC_DELETE,
                                            priority=2)
                    datapath.send_msg(mod)
                    self.stream[dpid].pop(port)


class RESTController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RESTController, self).__init__(req, link, data, **config)
        self.switch = data[switch_instance]

    @route('switch', '/mac', methods=['POST'])
    def post_data(self, req, **kwargs):
        data = json.loads(req.body)
        if 'port_no' in data:
            port_no = data['port_no']
        else:
            return Response(status=400)
        if 'mac' in data:
            mac = data['mac']
        else:
            return Response(status=400)
        if 'datapath_id' in data:
            datapath_id = data['datapath_id']
        else:
            return Response(status=400)
        self.switch.add_cooperated_device(port_no, mac, datapath_id)
        response = {'result': 'ok', 'code': 200}
        response_json = json.dumps(response)
        return Response(content_type='application/json', body=response_json)
