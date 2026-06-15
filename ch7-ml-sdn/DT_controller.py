from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switch
from datetime import datetime

import pandas as pd
import pickle
import time

class SimpleMonitor13(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):

        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_model = self.load_model()


    def load_model(self):
        print("MODEL LOADED -----------")
        model = pickle.load(open("trained_model_new.pkl", 'rb'))
        return model

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        print(f"STATE CHABGE dp = {datapath}")
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            print("...")
            self.req_send_time = time.time()
            for dp in self.datapaths.values():
                print(f"REQUESTING DP {dp} ---------")
                self._request_stats(dp)
            
            hub.sleep(10)
            # print("CALLING PREDICT ------")
            # self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        print(f"RECVD FLOW STATS REPLY------------------ in {time.time() - self.req_send_time} s from dp {ev.msg.datapath.id}")
        

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()

        file0 = open("PredictFlowStatsfile.csv","w")
        file0.write('flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,flow_duration,byte_count_per_second,packet_count_per_second,packet_count,byte_count\n')
        body = ev.msg.body
        # print("----------------------------------------------")
        # for stat in body:
        #     print(stat)
        # print("--
    
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            
                
            if stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(ip_dst) + str(tp_src) + str(tp_dst) + str(ip_proto)
            flow_id = flow_id.replace(".", "")
          
            try:
                packet_count_per_second = stat.packet_count/stat.duration_sec
            except:
                packet_count_per_second = 0
                
            try:
                byte_count_per_second = stat.byte_count/stat.duration_sec
            except:
                byte_count_per_second = 0
            
            flow_duration = int(stat.duration_sec) * 1000
            file0.write(f"{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},{flow_duration},{byte_count_per_second},{packet_count_per_second},{stat.packet_count},{stat.byte_count}\n")
            # print("STATS__________________________________________________________________________________________________________________________")
            # print(f"{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},{flow_duration},{byte_count_per_second},{packet_count_per_second},{stat.packet_count},{stat.byte_count}")
            # print("__________________________________________________________________________________________________________________________")
            # file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
            #     .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
            #             ip_proto,
            #             stat.duration_sec, stat.duration_nsec,
            #             stat.idle_timeout, stat.hard_timeout,
            #             stat.flags, stat.packet_count,stat.byte_count,
            #             packet_count_per_second,packet_count_per_nsecond,
            #             byte_count_per_second,byte_count_per_nsecond))
            
        file0.close()
        self.flow_predict()

    # def flow_training(self):

    #     self.logger.info("Flow Training ...")

    #     flow_dataset = pd.read_csv('FlowStatsfile.csv')

    #     flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
    #     flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
    #     flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

    #     X_flow = flow_dataset.iloc[:, :-1].values
    #     X_flow = X_flow.astype('float64')

    #     y_flow = flow_dataset.iloc[:, -1].values

    #     X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

    #     classifier = DecisionTreeClassifier(criterion='entropy', random_state=0)
    #     self.flow_model = classifier.fit(X_flow_train, y_flow_train)

    #     y_flow_pred = self.flow_model.predict(X_flow_test)

    #     self.logger.info("------------------------------------------------------------------------------")

    #     self.logger.info("confusion matrix")
    #     cm = confusion_matrix(y_flow_test, y_flow_pred)
    #     self.logger.info(cm)

    #     acc = accuracy_score(y_flow_test, y_flow_pred)

    #     self.logger.info("succes accuracy = {0:.2f} %".format(acc*100))
    #     fail = 1.0 - acc
    #     self.logger.info("fail accuracy = {0:.2f} %".format(fail*100))
    #     self.logger.info("------------------------------------------------------------------------------")

    def flow_predict(self):
        try:
            print(f"PREDICTING ---------------")
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

            predict_flow_dataset.iloc[:, 1] = predict_flow_dataset.iloc[:, 1].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')

            X_predict_flow = predict_flow_dataset.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float64')
            
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_trafic = 0
            ddos_trafic = 0
            
            # print(f"PRED = {y_flow_pred}")

            for i in y_flow_pred:
                if i == 0:
                    legitimate_trafic = legitimate_trafic + 1
                else:
                    ddos_trafic = ddos_trafic + 1
                    # victim = int(predict_flow_dataset.iloc[i, 5])%20

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_trafic/len(y_flow_pred)*100) > 70:
                self.logger.info("legitimate trafic ...")
                print(f"PREDICT IN TIME {time.time() - self.req_send_time} s")
            else:
                self.logger.info("ddos trafic ...")
                # self.logger.info("victim is host: h{}".format(victim))
                print(f"PREDICT IN TIME {time.time() - self.req_send_time} s")

            self.logger.info("------------------------------------------------------------------------------")
            
            file0 = open("PredictFlowStatsfile.csv","w")
            
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            file0.close()

        except Exception as e:
            print(f"EXC")
            pass