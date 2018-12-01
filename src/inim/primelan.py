'''
Created on 16 giu 2018

@author: Matteo
'''

import traceback
import socket
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from time import sleep
from contentcommon import ContentCommon
import requests

class PrimeConnectorEncrypt(object):
    
    BS = 16
    
    pad = lambda s: s + (PrimeConnectorEncrypt.BS - len(s) % PrimeConnectorEncrypt.BS) * chr(PrimeConnectorEncrypt.BS - len(s) % PrimeConnectorEncrypt.BS) 
    
    unpad = lambda s : s[0:-ord(s[-1])]
    
    @staticmethod
    def getRoundPKCS5(i):
        return ((i / 16) + 1) * 16
    
    def buildkey(self):
        h = MD5.new()
        h.update(self.user+self.passw)
        return h.digest()
    
    

    def encrypt(self,raw):
        return self.cypher.encrypt(PrimeConnectorEncrypt.pad(raw))
    
    def decrypt(self,enc):
        return PrimeConnectorEncrypt.unpad(self.cypher.decrypt(enc))

        #iv = Random.new().read(AES.block_size);

        #cipher = AES.new( self.key, AES.MODE_CBC, iv )

        #return ( iv + cipher.encrypt( raw ) ).encode("hex")
    
    def __init__(self,user,passw,codute):
        self.user = user
        self.passw = passw
        self.codute = codute
        self.key = self.buildkey()
        self.iv = []
        for i in range(0,len(self.key)):
            self.iv.append(i^self.key[i])
        self.cypher = AES.new(self.key, AES.MODE_CBC,self.iv)
        
class Params(object):
    def __init__(self):
        self.release = 0
        self.firmware = 0
        self.centrale = 0
        self.AGENTE = 0
        self.CAT_ALLARMI = 0
        self.CAT_AUT = 4
        self.CAT_ESC_CANC = 2
        self.CAT_GUASTI = 3
        self.CAT_INSERIMENTI = 1
        self.CAT_MISC = 5
        self.CMD_AREA_RESETAREA = 2
        self.CMD_READ_ESITO_COM_PC = 8196
        self.CMD_SCENARIO = 6
        self.CMD_USCITA_ATTDIS = 4
        self.CMD_ZONA_INCESC = 3
        self.COMMAND_SIZE_IBUS = 8
        self.COMM_TUTTAPPOSTO = 0
        self.DATA_FLASH = -2
        self.DETTAGLIO_1 = -1
        self.DETTAGLIO_2 = -2
        self.EEFLASH = -2
        self.EEP = -1
        self.EEPROM = -1
        self.EEPROM_NO_PROG = -3
        self.ELEMENTI_LOGGER = 0
        self.INIT = 0
        self.LOG_ALLARME_ZONA = 0
        self.LOG_ALL_ONVIF_1 = 100
        self.LOG_ALL_ONVIF_2 = 101
        self.LOG_ALL_ONVIF_3 = 102
        self.LOG_ALL_ONVIF_4 = 103
        self.LOG_ALL_ONVIF_5 = 104
        self.LOG_AREA = 11
        self.LOG_AREA_INSERITA_AWAY = 2
        self.LOG_AREA_INSERITA_STAY = 3
        self.LOG_AREA_NON_PRONTA = 7
        self.LOG_BATTERIA_BASSA = 39
        self.LOG_BATT_BASSA_ZONA_RADIO = 56
        self.LOG_CAMBIO_DATA_ORA = 71
        self.LOG_CAMPANELLO_SU_PART = 18
        self.LOG_CHIAMATA_SU_NUM_1 = 95
        self.LOG_CHIAMATA_SU_NUM_15 = 96
        self.LOG_CHIAVE = 4
        self.LOG_CHIAVE_FALSA = 60
        self.LOG_CHIAVE_RICO = 22
        self.LOG_CODICE = 3
        self.LOG_CODICE_RICO = 21
        self.LOG_COD_ERRATO = 59
        self.LOG_CONN_GPRS_PERSA = 99
        self.LOG_CONN_IP_PERSA = 98
        self.LOG_CREDITO_SCARSO = 70
        self.LOG_DISCONNECTED_BATT = 74
        self.LOG_DIS_AREA = 12
        self.LOG_ESCLUSIONE_ZONA = 5
        self.LOG_EVENTO_PROG = 31
        self.LOG_EXPANDER = 8
        self.LOG_FALLITO_SMS = 68
        self.LOG_FUS_IBUS_INTERROTTO = 38
        self.LOG_FUS_ZONE_INTERROTTO = 37
        self.LOG_GND_FAULT = 77
        self.LOG_GUASTO_GSM = 61
        self.LOG_ING_IN_PROG = 66
        self.LOG_INS_EFFET_PART = 10
        self.LOG_INS_EFFET_PART_STAY = 11
        self.LOG_INS_FORZ_PART = 19
        self.LOG_INTERV_TIMER = 28
        self.LOG_LIBERO_12 = 105
        self.LOG_LIBERO_13 = 106
        self.LOG_LIBERO_14 = 107
        self.LOG_LIBERO_15 = 108
        self.LOG_LIBERO_16 = 109
        self.LOG_LIBERO_17 = 110
        self.LOG_LIBERO_18 = 111
        self.LOG_LIBERO_19 = 112
        self.LOG_LIBERO_20 = 113
        self.LOG_LOG_70_PERCENTO = 64
        self.LOG_MALF_USCITA = 69
        self.LOG_MANCATO_INS_AREA = 20
        self.LOG_NO_COM_ALIMENTATORE = 94
        self.LOG_OSCURAMENTO_RADIO = 55
        self.LOG_OVERLOAD_1 = 90
        self.LOG_OVERLOAD_2 = 91
        self.LOG_OVERLOAD_3 = 92
        self.LOG_OVERLOAD_BUS = 93
        self.LOG_OVERVOLTAGE_1 = 78
        self.LOG_OVERVOLTAGE_2 = 79
        self.LOG_OVERVOLTAGE_3 = 80
        self.LOG_OVERVOLTAGE_BUS = 81
        self.LOG_PANICO_1 = 33
        self.LOG_PERIODIC_TEST_1 = 34
        self.LOG_POWER_OVERLOAD = 75
        self.LOG_POWER_OVER_HEATED = 76
        self.LOG_PROGRAMMABILE = 14
        self.LOG_PROXI = 10
        self.LOG_RESET_ALL_PART = 13
        self.LOG_RESET_DELLA_CENTRALE = 63
        self.LOG_RES_INTERNA_BATT = 72
        self.LOG_RETE_MANCANTE = 40
        self.LOG_RICH_INS_AREA = 8
        self.LOG_RICH_INS_AREA_STAY = 9
        self.LOG_RIC_CHI_SU_INS = 24
        self.LOG_RIC_CHI_SU_PART = 26
        self.LOG_RIC_COD_INST = 58
        self.LOG_RIC_COD_SU_PART = 25
        self.LOG_RIC_COD_SU_TAST = 23
        self.LOG_SABOTAGGIO_AREA = 4
        self.LOG_SABOTAGGIO_TERMINALE = 1
        self.LOG_SAB_ANTIAPERTURA = 35
        self.LOG_SAB_ANTISTRAPPO = 36
        self.LOG_SAB_EXP = 41
        self.LOG_SAB_LETTORE = 43
        self.LOG_SAB_SENS_VIDEO = 47
        self.LOG_SAB_SIRENA = 44
        self.LOG_SAB_SL_BUS = 45
        self.LOG_SAB_TAST = 42
        self.LOG_SAB_V_MONITOR = 46
        self.LOG_SCENARIO = 13
        self.LOG_SCEN_ATTIVATO = 30
        self.LOG_SCOMPARSA_SENS_VIDEO = 54
        self.LOG_SCOMPARSA_V_MONITOR = 53
        self.LOG_SCOMP_EXP = 48
        self.LOG_SCOMP_LETT = 50
        self.LOG_SCOMP_LINEA_TEL = 62
        self.LOG_SCOMP_SIRENA = 51
        self.LOG_SCOMP_SL_BUS = 52
        self.LOG_SCOMP_TAST = 49
        self.LOG_SCOMP_ZONA_RADIO = 57
        self.LOG_SENSO_VIDEO = 15
        self.LOG_SHORT_CIRCUIT_1 = 86
        self.LOG_SHORT_CIRCUIT_2 = 87
        self.LOG_SHORT_CIRCUIT_3 = 88
        self.LOG_SHORT_CIRCUIT_BATT = 73
        self.LOG_SHORT_CIRCUIT_BUS = 89
        self.LOG_SIRENA = 12
        self.LOG_STRAORD_SU_PART = 17
        self.LOG_SUPERT = 32
        self.LOG_SUPERTASTO = 7
        self.LOG_SYNC_DATI = 97
        self.LOG_TASTIERA = 9
        self.LOG_TELEFONATA_OK = 65
        self.LOG_TELEFONO = 5
        self.LOG_TEL_FALLITA = 27
        self.LOG_TEL_IN_CORSO = 67
        self.LOG_TEMPO_ING_PART = 15
        self.LOG_TEMPO_PER_PART = 16
        self.LOG_TEMPO_REALE_ZONA = 6
        self.LOG_TEMPO_USC_PART = 14
        self.LOG_TERMINALE = 2
        self.LOG_TERM_SU_TAST = 29
        self.LOG_TIMER = 6
        self.LOG_UNDERVOLTAGE_1 = 82
        self.LOG_UNDERVOLTAGE_2 = 83
        self.LOG_UNDERVOLTAGE_3 = 84
        self.LOG_UNDERVOLTAGE_BUS = 85
        self.LOG_ZONA = 1
        self.MAX_AREE = 0
        self.MAX_NUM_CHIAVI = 0
        self.MAX_NUM_CODICI = 0
        self.MAX_NUM_DATI_MODI_INS = 0
        self.MAX_NUM_DATI_ZONE = 0
        self.MAX_NUM_ESPANSIONI = 0
        self.MAX_NUM_MASK_USCITE = 0
        self.MAX_NUM_PROXI = 0
        self.MAX_NUM_SCENARI = 30
        self.MAX_NUM_SIRENE = 0
        self.MAX_NUM_STRUCT_CODICI = 0
        self.MAX_NUM_USCITE_FISSE = 3
        self.MAX_PIN_LENGHT = 6
        self.MAX_SDU_LENGHT = 1024
        self.NEXUS_CONNECTED = 3
        self.NEXUS_DISCONNECTED = 11
        self.NEXUS_GREETING_OK = 4
        self.NEXUS_OFFLINE = 10
        self.NEXUS_ONLINE = 9
        self.NUM_TASTIERE = 0
        self.N_RW_CHAR = 250
        self.PANEL_PACKET = 4
        self.RAM = 0
        self.RAM_DEVICE = 0
        self.RETURN_NO_PROBLEM = 0
        self.SERVER_CLOSED = 7
        self.SERVER_CLOSED_ERROR = 8
        self.SERVER_OPEN = 1
        self.SOCKACCEPT_ERROR = 6
        self.SOCKLISTEN_ERROR = 5
        self.SOCKOPEN_ERROR = 2        
        self.CMD_AREA_INSERIMENTI = 1
        self.CMD_AREA_INSERIMENTI_ADDRESS = 8198
        self.CMD_AREA_RESETAREA = 2
        self.CMD_AREA_RESETAREA_ADDRESS = 8200
        self.CMD_COMANDO_USCITA_ATTIVAZIONE = 1
        self.CMD_COMANDO_USCITA_DISATTIVAZIONE = 0
        self.CMD_COMANDO_ZONA_ESCLUSIONE = 1
        self.CMD_COMANDO_ZONA_INCLUSIONE = 0
        self.CMD_ESEGUI_SCENARIO = 8202
        self.CMD_LEGGI_GUASTI = 8197
        self.CMD_SCENARIO = 6
        self.CMD_USCITA_ATTDIS = 4
        self.CMD_USCITA_ATTDIS_ADDRESS = 8199
        self.CMD_ZONA_INCESC = 3
        self.CMD_ZONA_INCESC_ADDRESS = 8201
        self.Informazioni_stato_Zone_Uscite = 8195
        self.Leggi_sms = 32768
        self.MAX_CARATTERI = 16
        self.MAX_NUM_CHIAVI = [ 50, 50, 100, 100 ]
        self.MAX_NUM_DATI_TERMINALI = 12
        self.MAX_NUM_DESCRIZIONE_SCENARI = self.p.MAX_NUM_SCENARI * self.p.MAX_CARATTERI
        self.MAX_NUM_DESCRIZIONI_AREE = 0
        self.MAX_NUM_DESCRIZIONI_CHIAVI = 0
        self.MAX_NUM_DESCRIZIONI_CODICI = 0
        self.MAX_NUM_DESCRIZIONI_ESPANSIONI = 0
        self.MAX_NUM_DESCRIZIONI_NUMTEL = 0
        self.MAX_NUM_DESCRIZIONI_PROXI = 0
        self.MAX_NUM_DESCRIZIONI_SENSORIVIDEO = 0
        self.MAX_NUM_DESCRIZIONI_SIRENE = 0
        self.MAX_NUM_DESCRIZIONI_TASTIERE = 0
        self.MAX_NUM_DESCRIZIONI_ZONE = 0
        self.MAX_NUM_ESPANSIONI = [ 5, 10, 20, 40 ]
        self.MAX_NUM_LETTORI = [ 10, 10, 20, 30 ]
        self.MAX_NUM_LOGGER = 500
        self.MAX_NUM_LOGICI_10100 = 100
        self.MAX_NUM_LOGICI_1050 = 50
        self.MAX_NUM_LOGICI_505 = 10
        self.MAX_NUM_LOGICI_515 = 20
        self.MAX_NUM_PARTIZIONI = 0
        self.MAX_NUM_PARTIZIONI_10100 = 15
        self.MAX_NUM_PARTIZIONI_1050 = 10
        self.MAX_NUM_PARTIZIONI_505 = 5
        self.MAX_NUM_PARTIZIONI_515 = 5
        self.MAX_NUM_SCENARI = 30
        self.MAX_NUM_SENSORIVIDEO = [ 10, 10, 10, 10 ]
        self.MAX_NUM_SIRENE = [ 10, 10, 10, 10 ]
        self.MAX_NUM_STRUCT_LOGGER = 367
        self.MAX_NUM_STRUCT_MODI_INS = 0
        self.MAX_NUM_TERMINALI_10100 = 200
        self.MAX_NUM_TERMINALI_1050 = 100
        self.MAX_NUM_TERMINALI_505 = 20
        self.MAX_NUM_TERMINALI_515 = 40
        self.MAX_NUM_TERMINALI_FISICI = 0
        self.MAX_NUM_TERMINALI_FISICI_10100 = 240
        self.MAX_NUM_TERMINALI_FISICI_1050 = 130
        self.MAX_NUM_TERMINALI_FISICI_505 = 40
        self.MAX_NUM_TERMINALI_FISICI_515 = 70
        self.MAX_NUM_TERMINALI_LOGICI = 0
        self.MAX_NUM_TERMINALI_REALI_10100 = 100
        self.MAX_NUM_TERMINALI_REALI_1050 = 50
        self.MAX_NUM_TERMINALI_REALI_505 = 5
        self.MAX_NUM_TERMINALI_REALI_515 = 15
        self.MAX_NUM_TIMER = 0
        self.MAX_NUM_ZONE = 0
        self.Personalizzazione = 65234
        self.Zone_non_pronte = 8185
        self.aree = 0
        self.cmd_tastiere_presenti = 0
        self.com_read_stato_area = 8192
        self.com_read_stato_zone1 = 8194
        self.com_read_stato_zone2 = 8195
        self.com_read_tr_zone = 8193
        self.count_log_head = 0
        self.count_log_tail = 0
        self.eep_logger_ev = 0
        self.eep_pin_codici = 0
        self.eep_prg_codici = 0
        self.eep_prg_mod_ins = 0
        self.eep_prg_tastiere = 0
        self.eep_prg_term_cent = 0
        self.eep_prg_term_onboard = 0
        self.eep_prg_terminals = 0
        self.eep_prg_zones = 0
        self.eep_prog_termostato = 0
        self.infogsm = 8192
        self.k_revision = 16384
        self.k_revision_num = 12
        self.k_sw_str_aree = 16404
        self.k_sw_str_chiavi = 16416
        self.k_sw_str_codici = 16408
        self.k_sw_str_expander = 16414
        self.k_sw_str_mod_ins = 16420
        self.k_sw_str_numtel = 16418
        self.k_sw_str_proxi = 16410
        self.k_sw_str_rele = 16424
        self.k_sw_str_sens_video = 16442
        self.k_sw_str_sirene = 16430
        self.k_sw_str_timers = 16422
        self.k_sw_str_zone = 16406
        self.leggi_output = 8189
        self.max_num_infogsm = 22
        self.nome_tastiera = 16412
        self.tastier_cmdhoc = 8178
        self.temperatura_tastiera = 1882

class PrimelanConnector(object):
    CMD_PERSONALIZZAZIONE = 65234
    RAM = 0
    CMD_LEGGIOUTPUT = 8189
    CMD_UNKNOWN8184 = 8184
    COMM_TUTTAPPOSTO = 0
    MY_PERMISSIONS_REQUEST_SMS = 99
    k_revision_num = 12
    k_revision = 16384
    
    TABU8 = {
            0:-50,
            2:-50,
            4:-50,
            6:-50,
            8:-50,
            10:-50,
            12:-50,
            14:-50,
            16:-50,
            ContentCommon.MSG_TYPE_SET_ALARM:-50,
            1:-109,
            77:-109,
            3:-108,
            ContentCommon.DEFAULT_PORT:-108,
            5:-104,
            93:-104,
            7:-101,
            ContentCommon.MSG_TYPE_RESTORE_FACTORY:-98,
            11:-96,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUN5:-96,
            MY_PERMISSIONS_REQUEST_SMS:-96,
            13:-93,
            15:-90,
            17:-88,
            ContentCommon.MSG_TYPE_SET_PTZ:-87,
            ContentCommon.MSG_TYPE_WIFI_SCAN:-61,
            ContentCommon.MSG_TYPE_GET_RECORD:-61,
            ContentCommon.MSG_TYPE_SET_PPPOE:-61,
            26:-61,
            28:-61,
            32:-61,
            34:-61,
            38:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SET5:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SET6:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SET7:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SET8:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SET9:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SETA:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SETB:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SETC:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SETD:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SETE:-61,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SETF:-61,
            62:-61,
            64:-61,
            66:-61,
            68:-61,
            70:-61,
            72:-61,
            74:-61,
            76:-61,
            78:-61,
            80:-61,
            82:-61,
            84:-61,
            86:-61,
            ContentCommon.MSG_TYPE_GET_ALARM_LOG:-119,
            ContentCommon.MSG_TYPE_GET_RECORD_FILE:-95,
            117:-95,
            25:-87,
            27:-83,
            29:-77,
            119:-77,
            ContentCommon.CMD_PTZ_PREFAB_BIT_SET0:-59,
            36:-59,
            98:-59,
            100:-59,
            102:-59,
            104:-59,
            116:-59,
            118:-59,
            120:-59,
            122:-59,
            31:-111,
            33:-74,
            35:-70,
            37:-79,
            39:-68,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUN6:-94,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUN7:-89,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUN8:-86,
            103:-86,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUN9:-88,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUNA:-85,
            121:-85,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUNB:-82,
            97:-82,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUNC:-81,
            115:-81,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUND:-76,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUNE:-69,
            ContentCommon.CMD_PTZ_PREFAB_BIT_RUNF:-71,
            63:-75,
            65:-128,
            67:-127,
            69:-125,
            71:-126,
            73:-118,
            75:-115,
            109:-115,
            79:-107,
            83:-102,
            85:-92,
            87:-124,
            89:-124,
            88:-60,
            90:-60,
            92:-60,
            94:-60,
            96:-60,
            106:-60,
            108:-60,
            110:-60,
            112:-60,
            114:-60,
            91:-116,
            95:-106,
            101:-78,
            105:-67,
            107:-123,
            111:-103,
            113:-105,
            123:-66
             }
    
    
    #(read_d_d(share_applicazione_Comm_miobuff, 2, (int) this.mapparam.Personalizzazione, 2, this.RAM, (byte) 0, (byte) 0, (byte) 0)
    def read_d_d(self,buff,i,i2,i3,b,b2,b3,b4):
        b5 = 0
        if i > 4000:
            i5 = i % 4000;
            i6 = 0;
            i7 = i / 4000 + (0 if i5==0 else 1)
            i8 = 4000;
            b6 = 4;
            b5 = 0;
            while i6 < i7:
                if i5>0 and i6==i7-1:
                    i8 = i5
                else:
                    i8 = 4000
                r3 = bytearray('\x00'*i8)
                #r3 = new byte[i8];
                b7 = 0;
                b8 = b5;
                i4 = -1;
                r4 = b8;
                while i4 < 0 and b7 < b6:
                    SlRead = self.SlRead(r3, i2, i3, b, 0)
                    if SlRead < 0:
                        self.reconnect(0.3)
                        r4 = b7 + 1;
                    else:
                        r4 = b7
                    b5 = 1 if SlRead < 0 else  0
                    if b5 == 0:
                        buff[i6*4000:(i6*4000+i8)] = r3
                        #System.arraycopy(r3, 0, share_applicazione_Comm_miobuff.buffer, i6 * i, i);
                    b7 = r4;
                    r4 = b5;
                    i4 = SlRead;
                i6+=1;
                b5 = r4
        else:
            i8 = 8 if i2 == PrimelanConnector.CMD_LEGGIOUTPUT else i3
            r3 = bytearray('\x00' * i8)
            i4 = -1
            r10 = 0
            while i4 < 0 and r10 < 4:
                if i2!=PrimelanConnector.CMD_UNKNOWN8184:
                    i4 = self.SlRead(r3, i2, i3, b, b2)
                else:
                    i4 = self.SlRead(r3, i2, 1, i, i3)
                if i4 < 0:
                    self.reconnect(0.3)
                    r4 = (r10 + 1);
                else:
                    r4 = r10;
                r10 = r4;
            b5 = 1 if i4 < 0 else 0
            if b5 == 0:
                buff[0:i8] = r3
                #System.arraycopy(r3, 0, share_applicazione_Comm_miobuff.buffer, 0, i);
        return b5
    
    def SlRead(self,bArr, i, i2, i3, i4):
        i5 = 0;
        tries = 0;
        while tries < 3:
            if self.isConnected() or self.SLOpen() >= 0:
                i5 = self.SlReadTry(bArr, i, i2, i3, i4)
                if i5 == 0:
                    return i5
                self.SLClose()
                tries+=1
            else:
                self.SLClose()
                tries+=1
        print("Comunication ERROR. Please LOGOUT!.")
        return i5
    
    def SlReadTry(self,bArr,i,i2,i3,i4):
        if i3 == -1:
            i4 = i / 65536
        bArr2 = bytearray('\x00'*8)
        bArr2[1] = i4&0xFF
        bArr2[2] = i3&0xFF
        bArr2[3] = (i>>8)&0xFF
        bArr2[4] = i&0xFF
        bArr2[5] = (i2>>8)&0xFF
        bArr2[6] = i2&0xFF
        bArr2[7] = sum(bArr2[0:7])&0xFF
        try:
            self.sock.sendall(self.cyp.encrypt(bArr2))
            if i == 8191:
                i5 = 368
            elif i == 8187:
                i5 = PrimeConnectorEncrypt.getRoundPKCS5(i)
            elif i == 8184:
                i5 = 1;
            elif i == 8189:
                i5 = PrimeConnectorEncrypt.getRoundPKCS5(9);
            else:
                i6 = i2 + 1;
                i5 = PrimeConnectorEncrypt.getRoundPKCS5(i6);
            bArr2 = bytearray('\x00'*i5)
            i7 = 0
            while i7 < i5:
                try:
                    bArr2[i7] = self.sock.recv(1)
                    i7+=1
                except:
                    traceback.print_exc()
                    return -1
            bOut = self.cyp.decrypt(bArr2)
            bArr[0:len(bOut)] = bOut
            return 0
        except:
            traceback.print_exc()
            return -1
    
    def leggipersonalizzazione(self):
        buff = bytearray('\x00'*2)
        rv = self.read_d_d(buff, 2, PrimelanConnector.CMD_PERSONALIZZAZIONE, 2, PrimelanConnector.RAM, 0, 0, 0)
        if rv != PrimelanConnector.COMM_TUTTAPPOSTO:
            print('Command '+PrimelanConnector.CMD_PERSONALIZZAZIONE+' returned '+rv)
            return 0
        i = buff[0] + (buff[1] << 8)
        print('Personalizzazione is '+i)
        return 1
    
    @staticmethod
    def tabutf8(i):
        return PrimelanConnector.TABU8[i]+256 if i in PrimelanConnector.TABU8 else 0
    
    def InizializzaVariabili(self):
        if self.p.release==0:
            pass
        elif self.p.release==1:
            self.p.MAX_NUM_DATI_ZONE = 8
            if self.p.centrale==0:
                self.p.MAX_NUM_STRUCT_CODICI = 54
                self.p.eep_prg_terminals = 4522
                self.p.eep_prg_term_cent = 8192
                self.p.eep_prg_term_onboard = 4762
                self.p.eep_pin_codici = 5548
                self.p.eep_prg_codici = 5740
                self.p.eep_prg_zones = 4202
                self.p.eep_prg_mod_ins = 7768
                self.p.MAX_NUM_DATI_MODI_INS = 4
            elif self.p.centrale==1:
                self.p.MAX_NUM_STRUCT_CODICI = 58
                self.p.eep_prg_terminals = 8782
                self.p.eep_prg_term_cent = 15400
                self.p.eep_prg_term_onboard = 9382
                self.p.eep_pin_codici = 5548
                self.p.eep_prg_codici = 10570
                self.p.eep_prg_zones = 7982
                self.p.eep_prg_mod_ins = 14186
                self.p.MAX_NUM_DATI_MODI_INS = 7
                self.p.ELEMENTI_LOGGER = 500
            elif self.p.centrale==2:
                self.p.MAX_NUM_STRUCT_CODICI = 64
                self.p.eep_prg_terminals = 13476
                self.p.eep_prg_term_cent = 26352
                self.p.eep_prg_term_onboard = 16122
                self.p.eep_pin_codici = 17138
                self.p.eep_prg_codici = 17750
                self.p.eep_prg_zones = 13322
                self.p.eep_prg_mod_ins = 25178
                self.p.MAX_NUM_DATI_MODI_INS = 9
        elif self.p.release==3:
            self.p.MAX_NUM_DATI_ZONE = 9
            if self.p.centrale==0:
                self.p.MAX_NUM_STRUCT_CODICI = 54
                self.p.eep_prg_terminals = 7190
                self.p.eep_prg_term_cent = 12032
                self.p.eep_prg_term_onboard = 7430
                self.p.eep_pin_codici = 8988
                self.p.eep_prg_codici = 9180
                self.p.eep_prg_zones = 6830
                self.p.eep_prg_mod_ins = 11508
                self.p.eep_prog_termostato = 12800
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 12218
            elif self.p.centrale==1:
                self.p.MAX_NUM_STRUCT_CODICI = 58
                self.p.eep_prg_terminals = 13890
                self.p.eep_prg_term_cent = 22018
                self.p.eep_prg_term_onboard = 14490
                self.p.eep_pin_codici = 16176
                self.p.eep_prg_codici = 16488
                self.p.eep_prg_zones = 12990
                self.p.eep_prg_mod_ins = 20704
                self.p.eep_prog_termostato = 22624
                self.p.MAX_NUM_DATI_MODI_INS = 8
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 20944
                self.p.ELEMENTI_LOGGER = 500
            elif self.p.centrale==2:
                self.p.MAX_NUM_STRUCT_CODICI = 64
                self.p.eep_prg_terminals = 23830
                self.p.eep_prg_term_cent = 38456
                self.p.eep_prg_term_onboard = 25030
                self.p.eep_pin_codici = 28242
                self.p.eep_prg_codici = 28854
                self.p.eep_prg_zones = 22030
                self.p.eep_prg_mod_ins = 37182
                self.p.MAX_NUM_DATI_MODI_INS = 10
                self.p.eep_prog_termostato = 40448
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 39042
            elif self.p.centrale==3:
                self.p.MAX_NUM_STRUCT_CODICI = 53
                self.p.eep_prg_terminals = 5890
                self.p.eep_prg_term_cent = 10548
                self.p.eep_prg_term_onboard = 6010
                self.p.eep_pin_codici = 7536
                self.p.eep_prg_codici = 7728
                self.p.eep_prg_zones = 5710
                self.p.eep_prg_mod_ins = 10024
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.eep_prog_termostato = 12800
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 10685
        elif self.p.release==4:
            self.p.MAX_NUM_DATI_ZONE = 9
            if self.p.centrale==0:
                self.p.MAX_NUM_STRUCT_CODICI = 54
                self.p.eep_prg_terminals = 9025
                self.p.eep_prg_term_cent = 14112
                self.p.eep_prg_term_onboard = 9265
                self.p.eep_pin_codici = 10861
                self.p.eep_prg_codici = 11053
                self.p.eep_prg_zones = 8665
                self.p.eep_prg_mod_ins = 13381
                self.p.eep_prog_termostato = 28736
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 13531
                self.p.eep_logger_ev = 61020
            elif self.p.centrale==1:
                self.p.MAX_NUM_STRUCT_CODICI = 58
                self.p.eep_prg_terminals = 17355
                self.p.eep_prg_term_cent = 25502
                self.p.eep_prg_term_onboard = 17955
                self.p.eep_pin_codici = 19647
                self.p.eep_prg_codici = 19959
                self.p.eep_prg_zones = 16455
                self.p.eep_prg_mod_ins = 24175
                self.p.MAX_NUM_DATI_MODI_INS = 8
                self.p.eep_prog_termostato = 28736
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 24415
                self.p.eep_logger_ev = 61020
                self.p.ELEMENTI_LOGGER = 500
            elif self.p.centrale==2:
                self.p.MAX_NUM_STRUCT_CODICI = 64
                self.p.eep_prg_terminals = 29465
                self.p.eep_prg_term_cent = 44818
                self.p.eep_prg_term_onboard = 30665
                self.p.eep_pin_codici = 33985
                self.p.eep_prg_codici = 34597
                self.p.eep_prg_zones = 27665
                self.p.eep_prg_mod_ins = 42925
                self.p.MAX_NUM_DATI_MODI_INS = 10
                self.p.eep_prog_termostato = 98304
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 43225
                self.p.eep_logger_ev = 55556
            elif self.p.centrale==3:
                self.p.MAX_NUM_STRUCT_CODICI = 53
                self.p.eep_prg_terminals = 7515
                self.p.eep_prg_term_cent = 12419
                self.p.eep_prg_term_onboard = 7635
                self.p.eep_pin_codici = 9200
                self.p.eep_prg_codici = 9392
                self.p.eep_prg_zones = 7335
                self.p.eep_prg_mod_ins = 11688
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.eep_prog_termostato = 29760
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 11838
                self.p.eep_logger_ev = 61020
        elif self.p.release==5:
            self.p.MAX_NUM_DATI_ZONE = 9
            if self.p.centrale==0:
                self.p.MAX_NUM_STRUCT_CODICI = 54
                self.p.eep_prg_terminals = 9046
                self.p.eep_prg_term_cent = 14408
                self.p.eep_prg_term_onboard = 9286
                self.p.eep_pin_codici = 11162
                self.p.eep_prg_codici = 11354
                self.p.eep_prg_zones = 8686
                self.p.eep_prg_mod_ins = 13682
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.eep_prog_termostato = 29760
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 13832
                self.p.eep_logger_ev = 61020
            elif self.p.centrale==1:
                self.p.MAX_NUM_STRUCT_CODICI = 58
                self.p.eep_prg_terminals = 17376
                self.p.eep_prg_term_cent = 25793
                self.p.eep_prg_term_onboard = 17976
                self.p.eep_pin_codici = 19948
                self.p.eep_prg_codici = 20260
                self.p.eep_prg_zones = 16476
                self.p.eep_prg_mod_ins = 24476
                self.p.MAX_NUM_DATI_MODI_INS = 8
                self.p.eep_prog_termostato = 29760
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 24716
                self.p.eep_logger_ev = 61020
                self.p.ELEMENTI_LOGGER = 500
            elif self.p.centrale==2:
                self.p.MAX_NUM_STRUCT_CODICI = 64
                self.p.eep_prg_terminals = 29486
                self.p.eep_prg_term_cent = 45384
                self.p.eep_prg_term_onboard = 30686
                self.p.eep_pin_codici = 34566
                self.p.eep_prg_codici = 35178
                self.p.eep_prg_zones = 27686
                self.p.eep_prg_mod_ins = 43506
                self.p.MAX_NUM_DATI_MODI_INS = 10
                self.p.eep_prog_termostato = 98304
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 43806
                self.p.eep_logger_ev = 102404
            elif self.p.centrale==3:
                self.p.MAX_NUM_STRUCT_CODICI = 53
                self.p.eep_prg_terminals = 7536
                self.p.eep_prg_term_cent = 12715
                self.p.eep_prg_term_onboard = 7656
                self.p.eep_pin_codici = 9501
                self.p.eep_prg_codici = 9693
                self.p.eep_prg_zones = 7356
                self.p.eep_prg_mod_ins = 11989
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.eep_prog_termostato = 29760
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 12139
                self.p.eep_logger_ev = 61020
        elif self.p.release==6:
            self.p.MAX_NUM_DATI_ZONE = 9
            if self.p.centrale==0:
                self.p.MAX_NUM_STRUCT_CODICI = 55
                self.p.eep_prg_terminals = 12399
                self.p.eep_prg_term_cent = 17813
                self.p.eep_prg_term_onboard = 12639
                self.p.eep_pin_codici = 14535
                self.p.eep_prg_codici = 14727
                self.p.eep_prg_zones = 12039
                self.p.eep_prg_mod_ins = 17087
                self.p.eep_prog_termostato = 27392
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 17237
                self.p.eep_logger_ev = 61020
            elif self.p.centrale==1:
                self.p.MAX_NUM_STRUCT_CODICI = 59
                self.p.eep_prg_terminals = 22484
                self.p.eep_prg_term_cent = 30973
                self.p.eep_prg_term_onboard = 23084
                self.p.eep_pin_codici = 25076
                self.p.eep_prg_codici = 25388
                self.p.eep_prg_zones = 21584
                self.p.eep_prg_mod_ins = 29656
                self.p.eep_prog_termostato = 99328
                self.p.MAX_NUM_DATI_MODI_INS = 8
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 29896
                self.p.eep_logger_ev = 102916
                self.p.ELEMENTI_LOGGER = 1000
            elif self.p.centrale==2:
                self.p.MAX_NUM_STRUCT_CODICI = 65
                self.p.eep_prg_terminals = 37069
                self.p.eep_prg_term_cent = 53109
                self.p.eep_prg_term_onboard = 38269
                self.p.eep_pin_codici = 42189
                self.p.eep_prg_codici = 42801
                self.p.eep_prg_zones = 35269
                self.p.eep_prg_mod_ins = 51231
                self.p.eep_prog_termostato = 99328
                self.p.MAX_NUM_DATI_MODI_INS = 10
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 51531
                self.p.eep_logger_ev = 102916
            elif self.p.centrale==3:
                self.p.MAX_NUM_STRUCT_CODICI = 54
                self.p.eep_prg_terminals = 10609
                self.p.eep_prg_term_cent = 15840
                self.p.eep_prg_term_onboard = 10729
                self.p.eep_pin_codici = 12594
                self.p.eep_prg_codici = 12786
                self.p.eep_prg_zones = 10429
                self.p.eep_prg_mod_ins = 15114
                self.p.eep_prog_termostato = 27392
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 15264
                self.p.eep_logger_ev = 61020
        elif self.p.release==ContentCommon.MSG_TYPE_WIFI_SCAN:
            self.p.MAX_NUM_DATI_ZONE = 8
            if self.p.centrale==0:
                self.p.MAX_NUM_STRUCT_CODICI = 54
                self.p.eep_prg_terminals = 4520
                self.p.eep_prg_term_cent = 8522
                self.p.eep_prg_term_onboard = 4760
                self.p.eep_pin_codici = 5548
                self.p.eep_prg_codici = 5740
                self.p.eep_prg_zones = 4200
                self.p.eep_prg_mod_ins = 8068
                self.p.MAX_NUM_DATI_MODI_INS = 5
            elif self.p.centrale==1:
                self.p.MAX_NUM_STRUCT_CODICI = 58
                self.p.eep_prg_terminals = 8780
                self.p.eep_prg_term_cent = 16028
                self.p.eep_prg_term_onboard = 9380
                self.p.eep_pin_codici = 10256
                self.p.eep_prg_codici = 10570
                self.p.eep_prg_zones = 7980
                self.p.eep_prg_mod_ins = 14784
                self.p.MAX_NUM_DATI_MODI_INS = 8
                self.p.ELEMENTI_LOGGER = 500
            elif self.p.centrale==2:
                self.p.MAX_NUM_STRUCT_CODICI = 64
                self.p.eep_prg_terminals = 14920
                self.p.eep_prg_term_cent = 27286
                self.p.eep_prg_term_onboard = 16120
                self.p.eep_pin_codici = 17142
                self.p.eep_prg_codici = 17750
                self.p.eep_prg_zones = 13320
                self.p.eep_prg_mod_ins = 26082
                self.p.MAX_NUM_DATI_MODI_INS = 10
        elif self.p.release==ContentCommon.MSG_TYPE_GET_ALARM_LOG:
            self.p.MAX_NUM_DATI_ZONE = 8
            if self.p.centrale==0:
                self.p.MAX_NUM_STRUCT_CODICI = 54
                self.p.eep_prg_terminals = 4520
                self.p.eep_prg_term_cent = 8522
                self.p.eep_prg_term_onboard = 4760
                self.p.eep_pin_codici = 5548
                self.p.eep_prg_codici = 5740
                self.p.eep_prg_zones = 4200
                self.p.eep_prg_mod_ins = 8068
                self.p.MAX_NUM_DATI_MODI_INS = 5
            elif self.p.centrale==1:
                self.p.MAX_NUM_STRUCT_CODICI = 58
                self.p.eep_prg_terminals = 8780
                self.p.eep_prg_term_cent = 16028
                self.p.eep_prg_term_onboard = 9380
                self.p.eep_pin_codici = 10256
                self.p.eep_prg_codici = 17754
                self.p.eep_prg_zones = 7980
                self.p.eep_prg_mod_ins = 14784
                self.p.MAX_NUM_DATI_MODI_INS = 8
                self.p.ELEMENTI_LOGGER = 500
            elif self.p.centrale==2:
                self.p.MAX_NUM_STRUCT_CODICI = 64
                self.p.eep_prg_terminals = 14920
                self.p.eep_prg_term_cent = 27286
                self.p.eep_prg_term_onboard = 16120
                self.p.eep_pin_codici = 17142
                self.p.eep_prg_codici = 10568
                self.p.eep_prg_zones = 13320
                self.p.eep_prg_mod_ins = 26082
                self.p.MAX_NUM_DATI_MODI_INS = 10
            elif self.p.centrale==3:
                self.p.MAX_NUM_STRUCT_CODICI = 53
                self.p.eep_prg_terminals = 3760
                self.p.eep_prg_term_cent = 7578
                self.p.eep_prg_term_onboard = 3880
                self.p.eep_pin_codici = 4636
                self.p.eep_prg_codici = 4828
                self.p.eep_prg_zones = 3600
                self.p.eep_prg_mod_ins = 7124
                self.p.MAX_NUM_DATI_MODI_INS = 5
        elif self.p.release==ContentCommon.CMD_PTZ_PREFAB_BIT_RUNA:
            self.p.MAX_NUM_DATI_ZONE = 9
            if self.p.centrale==0:
                self.p.MAX_NUM_STRUCT_CODICI = 55
                self.p.eep_prg_terminals = 10260
                self.p.eep_prg_term_cent = 15654
                self.p.eep_prg_term_onboard = 10500
                self.p.eep_pin_codici = 12376
                self.p.eep_prg_codici = 12568
                self.p.eep_prg_zones = 9900
                self.p.eep_prg_mod_ins = 14928
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.eep_prog_termostato = 30528
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 15078
                self.p.eep_logger_ev = 61020
            elif self.p.centrale==1:
                self.p.MAX_NUM_STRUCT_CODICI = 59
                self.p.eep_prg_terminals = 18590
                self.p.eep_prg_term_cent = 27059
                self.p.eep_prg_term_onboard = 19190
                self.p.eep_pin_codici = 21162
                self.p.eep_prg_codici = 21474
                self.p.eep_prg_zones = 17690
                self.p.eep_prg_mod_ins = 25742
                self.p.MAX_NUM_DATI_MODI_INS = 8
                self.p.eep_prog_termostato = 30528
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 25982
                self.p.eep_logger_ev = 61020
                self.p.ELEMENTI_LOGGER = 500
            elif self.p.centrale==2:
                self.p.MAX_NUM_STRUCT_CODICI = 65
                self.p.eep_prg_terminals = 30700
                self.p.eep_prg_term_cent = 46700
                self.p.eep_prg_term_onboard = 31900
                self.p.eep_pin_codici = 35780
                self.p.eep_prg_codici = 36392
                self.p.eep_prg_zones = 28900
                self.p.eep_prg_mod_ins = 44822
                self.p.MAX_NUM_DATI_MODI_INS = 10
                self.p.eep_prog_termostato = 98304
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 45122
                self.p.eep_logger_ev = 102404
            elif self.p.centrale==3:
                self.p.MAX_NUM_STRUCT_CODICI = 54
                self.p.eep_prg_terminals = 8750
                self.p.eep_prg_term_cent = 13961
                self.p.eep_prg_term_onboard = 8870
                self.p.eep_pin_codici = 10715
                self.p.eep_prg_codici = 10907
                self.p.eep_prg_zones = 8570
                self.p.eep_prg_mod_ins = 13235
                self.p.MAX_NUM_DATI_MODI_INS = 5
                self.p.eep_prog_termostato = 30528
                self.p.cmd_tastiere_presenti = 3324
                self.p.eep_prg_tastiere = 13385
                self.p.eep_logger_ev = 61020
        self.p.MAX_NUM_STRUCT_MODI_INS = self.p.MAX_NUM_SCENARI * self.p.MAX_NUM_DATI_MODI_INS
        if self.p.centrale==0:
            self.p.MAX_NUM_DESCRIZIONI_AREE = self.p.MAX_CARATTERI * self.p.MAX_NUM_PARTIZIONI_515
            self.p.MAX_NUM_PARTIZIONI = self.p.MAX_NUM_PARTIZIONI_515
            self.p.MAX_NUM_DESCRIZIONI_ZONE = self.p.MAX_CARATTERI * self.p.MAX_NUM_TERMINALI_REALI_515
            self.p.MAX_NUM_ZONE = self.p.MAX_NUM_TERMINALI_REALI_515
            self.p.MAX_NUM_TERMINALI_LOGICI = self.p.MAX_NUM_LOGICI_515
            self.p.MAX_NUM_TERMINALI_FISICI = self.p.MAX_NUM_TERMINALI_FISICI_515
            self.p.MAX_NUM_LOGGER = 500
            self.p.MAX_NUM_CODICI = 30
            self.p.NUM_TASTIERE = 5
            self.p.MAX_NUM_MASK_USCITE = 4
            self.p.MAX_AREE = self.p.MAX_NUM_PARTIZIONI
            self.p.ELEMENTI_LOGGER = 500
            self.p.MAX_NUM_CHIAVI = 50
            self.p.MAX_NUM_PROXI = 10
            self.p.MAX_NUM_DESCRIZIONI_CHIAVI = self.p.MAX_NUM_CHIAVI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_CODICI = self.p.MAX_NUM_CODICI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_PROXI = self.p.MAX_NUM_PROXI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_NUMTEL = self.p.MAX_CARATTERI * 15
            self.p.MAX_NUM_DESCRIZIONI_SIRENE = self.p.MAX_NUM_SIRENE[1] * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_ESPANSIONI = self.p.MAX_NUM_ESPANSIONI[1] * self.p.MAX_CARATTERI
            self.p.MAX_NUM_TIMER = 10
            self.p.MAX_NUM_DESCRIZIONI_TASTIERE = self.p.NUM_TASTIERE
            self.p.MAX_NUM_DESCRIZIONI_SENSORIVIDEO = self.p.MAX_NUM_SENSORIVIDEO[0] * self.p.MAX_CARATTERI
        elif self.p.centrale==1:
            self.p.MAX_NUM_DESCRIZIONI_AREE = self.p.MAX_CARATTERI * self.p.MAX_NUM_PARTIZIONI_1050
            self.p.MAX_NUM_PARTIZIONI = self.p.MAX_NUM_PARTIZIONI_1050
            self.p.MAX_NUM_DESCRIZIONI_ZONE = self.p.MAX_CARATTERI * self.p.MAX_NUM_TERMINALI_REALI_1050
            self.p.MAX_NUM_ZONE = self.p.MAX_NUM_TERMINALI_REALI_1050
            self.p.MAX_NUM_TERMINALI_LOGICI = self.p.MAX_NUM_LOGICI_1050
            self.p.MAX_NUM_TERMINALI_FISICI = self.p.MAX_NUM_TERMINALI_FISICI_1050
            self.p.MAX_NUM_LOGGER = 500
            self.p.MAX_NUM_CODICI = 50
            self.p.MAX_NUM_MASK_USCITE = 8
            self.p.NUM_TASTIERE = 10
            self.p.MAX_AREE = self.p.MAX_NUM_PARTIZIONI
            self.p.ELEMENTI_LOGGER = 500
            self.p.MAX_NUM_CHIAVI = 100
            self.p.MAX_NUM_PROXI = 20
            self.p.MAX_NUM_DESCRIZIONI_CODICI = self.p.MAX_NUM_CODICI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_PROXI = self.p.MAX_NUM_PROXI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_NUMTEL = self.p.MAX_CARATTERI * 15
            self.p.MAX_NUM_DESCRIZIONI_SIRENE = self.p.MAX_NUM_SIRENE[2] * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_ESPANSIONI = self.p.MAX_NUM_ESPANSIONI[2] * self.p.MAX_CARATTERI
            self.p.MAX_NUM_TIMER = 10
            self.p.MAX_NUM_DESCRIZIONI_TASTIERE = self.p.NUM_TASTIERE
            self.p.MAX_NUM_DESCRIZIONI_SENSORIVIDEO = self.p.MAX_NUM_SENSORIVIDEO[0] * self.p.MAX_CARATTERI
        elif self.p.centrale==2:
            self.p.MAX_NUM_DESCRIZIONI_AREE = self.p.MAX_CARATTERI * self.p.MAX_NUM_PARTIZIONI_10100
            self.p.MAX_NUM_PARTIZIONI = self.p.MAX_NUM_PARTIZIONI_10100
            self.p.MAX_NUM_DESCRIZIONI_ZONE = self.p.MAX_CARATTERI * self.p.MAX_NUM_TERMINALI_REALI_10100
            self.p.MAX_NUM_ZONE = self.p.MAX_NUM_TERMINALI_REALI_10100
            self.p.MAX_NUM_TERMINALI_LOGICI = self.p.MAX_NUM_LOGICI_10100
            self.p.MAX_NUM_TERMINALI_FISICI = self.p.MAX_NUM_TERMINALI_FISICI_10100
            self.p.MAX_NUM_LOGGER = 1000
            self.p.MAX_NUM_CODICI = 100
            self.p.MAX_NUM_MASK_USCITE = 14
            self.p.NUM_TASTIERE = 15
            self.p.MAX_AREE = self.p.MAX_NUM_PARTIZIONI
            self.p.ELEMENTI_LOGGER = 1000
            self.p.MAX_NUM_CHIAVI = 150
            self.p.MAX_NUM_PROXI = 30
            self.p.MAX_NUM_DESCRIZIONI_CODICI = self.p.MAX_NUM_CODICI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_PROXI = self.p.MAX_NUM_PROXI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_NUMTEL = self.p.MAX_CARATTERI * 15
            self.p.MAX_NUM_DESCRIZIONI_SIRENE = self.p.MAX_NUM_SIRENE[3] * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_ESPANSIONI = self.p.MAX_NUM_ESPANSIONI[3] * self.p.MAX_CARATTERI
            self.p.MAX_NUM_TIMER = 20
            self.p.MAX_NUM_DESCRIZIONI_TASTIERE = self.p.NUM_TASTIERE
            self.p.MAX_NUM_DESCRIZIONI_SENSORIVIDEO = self.p.MAX_NUM_SENSORIVIDEO[0] * self.p.MAX_CARATTERI
        elif self.p.centrale==3:
            self.p.MAX_NUM_DESCRIZIONI_AREE = self.p.MAX_CARATTERI * self.p.MAX_NUM_PARTIZIONI_505
            self.p.MAX_NUM_PARTIZIONI = self.p.MAX_NUM_PARTIZIONI_505
            self.p.MAX_NUM_DESCRIZIONI_ZONE = self.p.MAX_CARATTERI * self.p.MAX_NUM_TERMINALI_REALI_505
            self.p.MAX_NUM_ZONE = self.p.MAX_NUM_TERMINALI_REALI_505
            self.p.MAX_NUM_TERMINALI_LOGICI = self.p.MAX_NUM_LOGICI_505
            self.p.MAX_NUM_TERMINALI_FISICI = self.p.MAX_NUM_TERMINALI_FISICI_505
            self.p.MAX_NUM_LOGGER = 500
            self.p.MAX_NUM_CODICI = 30
            self.p.MAX_NUM_MASK_USCITE = 3
            self.p.NUM_TASTIERE = 5
            self.p.MAX_AREE = self.p.MAX_NUM_PARTIZIONI
            self.p.ELEMENTI_LOGGER = 500
            self.p.MAX_NUM_CHIAVI = 50
            self.p.MAX_NUM_PROXI = 10
            self.p.MAX_NUM_DESCRIZIONI_CODICI = self.p.MAX_NUM_CODICI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_PROXI = self.p.MAX_NUM_PROXI * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_NUMTEL = self.p.MAX_CARATTERI * 15
            self.p.MAX_NUM_DESCRIZIONI_SIRENE = self.p.MAX_NUM_SIRENE[0] * self.p.MAX_CARATTERI
            self.p.MAX_NUM_DESCRIZIONI_ESPANSIONI = self.p.MAX_NUM_ESPANSIONI[0] * self.p.MAX_CARATTERI
            self.p.MAX_NUM_TIMER = 10
            self.p.MAX_NUM_DESCRIZIONI_TASTIERE = self.p.NUM_TASTIERE
            self.p.MAX_NUM_DESCRIZIONI_SENSORIVIDEO = self.p.MAX_NUM_SENSORIVIDEO[0] * self.p.MAX_CARATTERI
    
    @staticmethod
    def byteToStr(bArr, i):
        bArr2 = '  '
        strv = unicode(ContentCommon.DEFAULT_USER_PWD)
        i2 = 0;
        while i2 < i:
            if bArr[i2]>=128:
                bArr2[0] = PrimelanConnector.tabutf8((bArr[i2] - 128) * 2)
                bArr2[1] = PrimelanConnector.tabutf8(((bArr[i2] - 128) * 2) + 1)
                
                try:
                    strv+=bArr2.decode('utf-8')
                except:
                    traceback.print_exc()
            else:
                strv+=bArr[i2]
            i2+=1
        return strv
    
    def LeggiRevisioneFirmwareNoMsg(self):
        buff = bytearray('\x00'*PrimelanConnector.k_revision_num)
        i = 0;
        while 1:
            read_d_d = self.read_d_d(buff, PrimelanConnector.k_revision_num, PrimelanConnector.k_revision, PrimelanConnector.k_revision_num, PrimelanConnector.RAM, 0, 0, 0)
            if ((1 if i < 3 else 0) & (1 if read_d_d != PrimelanConnector.COMM_TUTTAPPOSTO else 0)) == 0:
                break;
            sleep(0.2)
            #b = (i + 1)
        if read_d_d != PrimelanConnector.COMM_TUTTAPPOSTO:
            return 0
        byteToStr = PrimelanConnector.byteToStr(buff, PrimelanConnector.k_revision_num);
        fc = ord(byteToStr[0])
        if fc==ContentCommon.CMD_PTZ_PREFAB_BIT_SET9:
            self.p.release = 0
            self.p.firmware = 0
        elif fc==ContentCommon.CMD_PTZ_PREFAB_BIT_RUN9:
            self.p.release = 1
            self.p.firmware = 1
        elif fc==ContentCommon.CMD_PTZ_PREFAB_BIT_SETA:
            sc = ord(byteToStr[2])
            if sc==ContentCommon.CMD_PTZ_PREFAB_BIT_SET9:
                self.p.release = 20
                self.p.firmware = 2
            elif sc==ContentCommon.CMD_PTZ_PREFAB_BIT_RUN9:
                self.p.release = 21
                self.p.firmware = 2
        elif fc==ContentCommon.CMD_PTZ_PREFAB_BIT_RUNA:
            self.p.release = 3
            self.p.firmware = 3
        elif fc==ContentCommon.CMD_PTZ_PREFAB_BIT_SETB:
            self.p.release = 4
            self.p.firmware = 4
        elif fc==ContentCommon.CMD_PTZ_PREFAB_BIT_RUNB:
            sc = ord(byteToStr[2])
            if sc==ContentCommon.CMD_PTZ_PREFAB_BIT_SET9:
                self.p.release = 5
                self.p.firmware = 5
            elif sc==ContentCommon.CMD_PTZ_PREFAB_BIT_RUN9:
                self.p.release = 51
                self.p.firmware = 5
        if fc==ContentCommon.CMD_PTZ_PREFAB_BIT_SETC:
                sc = ord(byteToStr[2])
                if sc==ContentCommon.CMD_PTZ_PREFAB_BIT_SET9:
                    self.p.release = 6
                    self.p.firmware = 6
                elif sc==ContentCommon.CMD_PTZ_PREFAB_BIT_RUN9:
                    self.p.release = 6
                    self.p.firmware = 7
        if byteToStr.charAt[5] == '1':
            self.p.centrale = 2
        elif byteToStr.charAt[6] == '1':
            self.p.centrale = 1;
        elif byteToStr.charAt[8] == '1':
            self.p.centrale = 0;
        else:
            self.p.centrale = 3
        self.InizializzaVariabili()
        TrovaMascheraAree(str, 0);
        if (Config.Tipo_personalizzazione == share_applicazione_glob.CLIENTI_HESA) {
            char[] toCharArray;
            if (byteToStr.charAt(0) == '5') {
                toCharArray = byteToStr.toCharArray();
                toCharArray[0] = (char) 49;
                byteToStr = String.valueOf(toCharArray);
            } else {
                toCharArray = byteToStr.toCharArray();
                toCharArray[0] = (char) 50;
                byteToStr = String.valueOf(toCharArray);
            }
        }
        share_applicazione_glob.setDescrizione(byteToStr);
        share_applicazione_glob.setflaglettura();
        return true;
    
    def __init__(self,user,passw,codute,host,port,timeout=5):
        self.timeout = timeout
        self.cyp = PrimeConnectorEncrypt(user, passw, codute)
        self.sock = None
        self.hp = (host,port)
        self.p = Params()
    
    def isConnected(self):
        return self.sock is not None
    
    def reconnect(self,wait):
        self.SLClose()
        sleep(wait)
        self.SLOpen()
    
    def SLClose(self):
        if self.isConnected():
            try:
                self.sock.close()
            except:
                traceback.print_exc()
            self.sock = None
            
        
    def SLOpen(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        try:
            self.sock.settimeout(15)
            self.sock.connect(self.hp)
            self.sock.settimeout(self.timeout)
            return 0
        except:
            traceback.print_exc()
            self.sock = None
            return -1

    def stop(self):
        pass

    def send_packet(self, addr, packet):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        try:
            sock.settimeout(self.timeout)
            sock.connect(addr)
            sock.sendall(bytearray(packet))
            sock.close()
            return len(packet)
        except:
            traceback.print_exc()
            return -1