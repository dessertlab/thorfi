import flask
from flask import Flask

class InjectorAgent():


    def __init__(self, ip, port, threaded=True, debug=False):

        self.injectorAgent = Flask(__name__)
        self.ip = ip
        self.port = port
        self.threaded = threaded
        self.debug = debug


    def getIp(self):
          return self.ip


    def getPort(self):
          return int(self.port)

    def getThreaded(self):
          return bool(self.threaded)

    def getDebug(self):
          return self.debug

    def getInjectorAgent(self):
          return self.injectorAgent



    def run(self):

          agent = self.getInjectorAgent()

          print self.getDebug()

          agent.run(host = self.getIp(),
                      port = self.getPort(),
                      threaded = self.getThreaded(),
                      debug = self.getDebug())
