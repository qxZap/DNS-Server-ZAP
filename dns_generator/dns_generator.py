import json
import os
import socket

QUESTION_TYPES = {
    b"\x00\x01": "a"
}
ZONES = {}  # Holds hostname -> record data, cannot grow as server runs

def createRecords(domain_ip,ttl=400,name='@'):
    return {'name':name,'ttl':ttl,'value':domain_ip}

def getCustomRecordsForIP(domain_ip,ttl=400,name='@'):
    return [createRecords(domain_ip,ttl,name),createRecords('192.168.0.1',ttl,name)]

def getIpFromBytes(bytes):
    domain = []
    expected_size = None
    domain_component = ""
    byteRead = 0
    total_bytes_read=0
    for byte in bytes:
        if expected_size == None:
            expected_size = byte
            byteRead = 0
        else:
            if byteRead < expected_size:
                domain_component+=chr(byte)
                byteRead +=1
            else:
                domain.append(domain_component)
                expected_size=byte
                byteRead = 0
                domain_component=""
        if byte == 0:
            break
        total_bytes_read+=1
    return domain , bytes[total_bytes_read:total_bytes_read+2]           

def DNStoIP(domain_name):
    domain_ip = None
    try:
        domain_ip = socket.gethostbyname(domain_name)
    except socket.gaierror:
        domain_ip = None
    return domain_ip

def load_zones():
    global ZONES
    json_zone = {}
    zones_path = "Zones"
    files = []
    try:
        files = os.listdir(zones_path)
    except FileNotFoundError:
        zones_path = "..\Zones"
        files = os.listdir(zones_path)
    for zone_file in os.listdir(zones_path):
        with open(os.path.join(zones_path, zone_file), "r") as f:
            data = json.load(f)
            zone_name = data["$origin"]
            json_zone[zone_name] = data
    return json_zone
ZONES = load_zones()

def get_zone(domain):
        global ZONES
        zone_name = ".".join(domain)
        zone = {}
        try:
            zone = ZONES[zone_name]
        except KeyError:
            return None
        return zone

class DNSGen(object):

    def __init__(self, data):
        self.data = data
        self.QR = "1"
        self.AA = "1"
        self.TC = "0"
        self.RD = "0"
        self.RA = "0"   # 0=No Recursion Available
        self.Z = "000"
        self.RCODE = "0000"
        self.QDCOUNT = b"\x00\01"   # Answer only 1 question for now
        self.NSCOUNT = b"\x00\x00"  # Nameserver count
        self.ARCOUNT = b"\x00\x00"  # Additional records
        self.format_error = 0       # 1=Error in trying to parse domain parts
        self.domain = ""

    def _get_transaction_id(self):
        return self.data[0:2]  # first 2 bytes have transaction ID

    def _get_opcode(self):
        byte1 = self.data[2:3]    # get 1 byte after transaction id
        opcode = ""
        for bit in range(1, 5):	    # loop bits till end of OPCODE bit
            opcode += str(ord(byte1) & (1 << bit))	   # ord converts byte to unicode int
        return opcode

    def _generate_flags(self):
        flags1 = int(self.QR + self._get_opcode() + self.AA + self.TC + self.RD, 2).to_bytes(1, byteorder="big")
        flags2 = int(self.RA + self.Z + self.RCODE).to_bytes(1, byteorder="big")
        return flags1 + flags2

    def _get_question_domain_type(self, data):
        domain , question_type = getIpFromBytes(data)
        self.domain = domain
        self.format_error = 0

        return domain , question_type

    def _get_records(self, data):
        domain, question_type = self._get_question_domain_type(data)
        if question_type is None and len(domain) == 0:
            return {}, "", ""
        qt = ""
        try:
            qt = QUESTION_TYPES[question_type]
        except KeyError:
            qt = "a"
        zone = get_zone(domain)
        if zone is None:
            return [], qt, domain   # empty list ensure a domain we don't have returns correct data
        return zone[qt], qt, domain

    @staticmethod
    def _record_to_bytes(domain_name, record_type, record_ttl, record_value):
        plain = "\xc0\x0c"
        resp = b"\xc0\x0c"
        if record_type == "a":
            plain+="\x00\x01"
            resp += b"\x00\x01"
        resp += b"\x00\x01"    # class IN
        plain+="\x00\x01"
        resp += int(record_ttl).to_bytes(4, byteorder="big")    # ttl in bytes
        plain+= str(int(record_ttl))
        if record_type == "a":
            plain+="\x00\x04" 
            resp += b"\x00\x04"    # IP length
            for part in record_value.split("."):
                plain+=str([int(part)])
                resp += bytes([int(part)])
        # print(plain)
        return resp

    def _make_header(self, records_length):
        transaction_id = self._get_transaction_id()
        ancount = records_length.to_bytes(2, byteorder="big")
        if self.format_error == 1:
            self.RCODE = "0001"  # Format error
        elif ancount == b"\x00\x00":
            self.RCODE = "0003"  # Name error
        flags = self._generate_flags()  # relies on state variable self.RCODE, which modified above if appropriate
        return transaction_id + flags + self.QDCOUNT + ancount + self.NSCOUNT + self.ARCOUNT

    def _make_question(self, records_length, record_type, domain_name):
        resp = b""
        if self.format_error == 1:
            return resp
        for part in domain_name:
            length = len(part)
            resp += bytes([length])
            for char in part:
                resp += ord(char).to_bytes(1, byteorder="big")
        resp += b"\x00"    # end labels
        if record_type == "a":
            resp += (1).to_bytes(2, byteorder="big")
        resp += (1).to_bytes(2, byteorder="big")
        return resp

    def _make_answer(self, records, record_type, domain_name):
        resp = b""
        if len(records) == 0 or self.format_error == 1:
            return resp
        for record in records:
            resp += self._record_to_bytes(domain_name, record_type, record["ttl"], record["value"])

        return resp

    def make_response(self):
        records, record_type, domain_name = self._get_records(self.data[12:])
        if records == []:
            domain_ip = DNStoIP('.'.join(domain_name))
            if( domain_ip != None):
                records = getCustomRecordsForIP(domain_ip)
        header = self._make_header(len(records))
        question = self._make_question(len(records), record_type, domain_name)
        answer = self._make_answer(records, record_type, domain_name)
        return  header + question + answer

if __name__ == "__main__":
    pass
