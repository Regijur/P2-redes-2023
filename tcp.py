import asyncio
from tcputils import *
import time
import math
import secrets

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = self.inic_conexao(id_conexao, segment)
            if self.callback:
                self.callback(conexao)
                
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

    def enviar(self, data, id_conexao):
        self.rede.enviar(data, id_conexao)

    def inic_conexao(self, id_conexao, segment):
        _, _, seq_no, _, flags, _, _, _ = read_header(segment)
        src_addr, src_port, dst_addr, dst_port = id_conexao
        ack_no = seq_no + 1
        seq_no = secrets.randbelow(10)
        seg_ack = make_header(dst_port, src_port, seq_no, ack_no, FLAGS_ACK | FLAGS_SYN)
        seg_ack = fix_checksum(seg_ack, src_addr, dst_addr)
        self.enviar(seg_ack, src_addr)
        return Conexao(self, id_conexao, ack_no, seq_no + 1)

class Conexao:
    def __init__(self, servidor, id_conexao, ack_no, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.window = 1
        self.callback = None
        self.initialTime = None
        self.finalTime = None
        self.timer = None
        self.devr = None  
        self.ack_no = ack_no
        self.seq_no = seq_no
        self.sendb = seq_no
        self.last_seq = seq_no
        self.unacked = b""
        self.unsent = b""
        self.byt_ack = 0
        self.interv = 0.2
        self.iter_inic = True
        self.closing = False
        self.resend_message = False
        
    def timeout(self):
        self.timer = None
        self.window = max(self.window // 2, 1)
        self.resend()
        self.timerstart()

    def timerstart(self):
        if self.timer:
            self.timestop()
        self.timer = asyncio.get_event_loop().call_later(self.interv, self.timeout)
        
    def timestop(self):
        self.timer.cancel()
        self.timer = None

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if self.ack_no != seq_no:
            return
        
        if (flags & FLAGS_ACK) == FLAGS_ACK and self.closing:
            del self.servidor.conexoes[self.id_conexao]
            return
        
        if (flags & FLAGS_FIN) == FLAGS_FIN and not self.closing:
            self.closing = True 
            self.callback(self, b"")
            self.ack_no = self.ack_no + 1
            self.sendACK(b"") 
        
        
        if self.byt_ack == MSS:
            self.byt_ack = self.byt_ack + MSS
            self.window = self.window + 1
            self.pendingSend()


        if(flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.sendb :
            self.unacked = self.unacked[ack_no - self.sendb :]
            self.byt_ack = ack_no - self.sendb
            self.sendb = ack_no
     
            if self.unacked:
                self.timerstart()
            else:
                if self.timer:
                    self.timestop()
                if not self.resend_message:
                    self.finalTime = time.time()
                    self.rtt()   
                else:
                    self.resend_message = False
    
        if payload:
            self.ack_no = self.ack_no + len(payload)
            self.callback(self, payload)
            pac = fix_checksum(make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, self.ack_no, flags), self.id_conexao[0], self.id_conexao[2],)
            self.servidor.enviar(pac, self.id_conexao[2])

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        self.unsent = self.unsent + dados
        complete = self.unsent[: (self.window * MSS)]
        self.unsent = self.unsent[(self.window * MSS) :]
        self.last_seq = self.seq_no + len(complete)
        n_segment = math.ceil(len(complete) / MSS)
        for index in range(n_segment):
            segment = complete[index * MSS : (index + 1) * MSS]
            self.sendACK(segment)
        

    def fechar(self):
        ack_segment = make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, self.ack_no, FLAGS_FIN)
        self.servidor.enviar(fix_checksum(ack_segment, self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0])
        
    def resend(self):
        self.resend_message = True
        size = min(MSS, len(self.unacked))
        data = self.unacked[:size]
        self.sendACK(data)

    def sendACK(self, data):
        seq_no = self.sendb

        if not self.resend_message:
            seq_no = self.seq_no
            self.seq_no = self.seq_no + len(data)
            self.unacked = self.unacked + data
            self.initialTime = time.time() 

        header = make_header(self.id_conexao[1], self.id_conexao[3], seq_no, self.ack_no, FLAGS_ACK)
        segment = fix_checksum(header + data, self.id_conexao[0], self.id_conexao[2])
        
        self.servidor.enviar(segment, self.id_conexao[1])

        if not self.timer and not self.closing:
            self.timerstart()

    def pendingSend(self):
        size = (self.window * MSS) - len(self.unacked)
        if size > 0:
            complete = self.unsent[:size]
            self.unsent = self.unsent[size:]
            self.last_seq = self.seq_no + len(complete)
            n_segment = math.ceil(len(complete) / MSS)
            
            for i in range(n_segment):
                segment = complete[i * MSS : (i + 1) * MSS]
                self.sendACK(segment)
                         
    def rtt(self):
        self.sample_rtt = self.finalTime - self.initialTime
        if self.iter_inic:
            self.iter_inic = False
            self.devr = self.sample_rtt / 2
            self.estimated = self.sample_rtt
        else:
            self.estimated = ((0.75) * self.estimated) + (0.25 * self.sample_rtt)
            self.devr = ((0.5) * self.devr) + (0.5 * abs(self.sample_rtt - self.estimated))
        self.interv = self.estimated + (4 * self.devr)
