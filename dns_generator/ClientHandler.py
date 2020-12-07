import threading
from dns_generator import DNSGen


class ClientHandler(threading.Thread):
    """
    Class to handle multiple client DNS requests
    """

    def __init__(self, address, data, sock):
        threading.Thread.__init__(self)
        self.client_address = address
        self.dns_gen = DNSGen(data)
        self.sock = sock

    def run(self):
        response = self.dns_gen.make_response()
        self.sock.sendto(response, self.client_address)
        print("Request from {0} for {1}".format(self.client_address, self.dns_gen.domain))
