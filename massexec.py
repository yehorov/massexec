#!/usr/bin/env python

from twisted.conch.ssh import transport, userauth, agent, connection, common, keys, channel
from twisted.conch.ssh import filetransfer
from twisted.internet import defer, protocol, reactor
from twisted.python import log, usage, filepath
import struct, sys, os, getpass


class MassExecMultiple():

    DEFAULT_PORT = 22

    def __init__(self, options):
        self.options = options
        self.hosts = []
        self.hosts.extend(options['hosts'])
        self.runclients = 0
        self.freeclients = options['multiple']
        self.results = dict()

    def nextClient(self, newclient = False):
        if not newclient:
            self.runclients -= 1
            self.freeclients += 1

        if self.freeclients <= 0:
            return 0

        if len(self.hosts) > 0:
            host = self.hosts.pop(0)
        else:
            if self.runclients <= 0:
                self.printResults()
                reactor.stop()
            return 0

        if '@' in host:
            user, host = host.split('@', 1)
        else:
            user = options['user']

        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = MassExecMultiple.DEFAULT_PORT

        self.runclients += 1
        self.freeclients -= 1
        factory = SSHExecFactory(user, host, port, self.options, self)
        bindaddress = (self.options['bind'], 0) if self.options['bind'] else None
        reactor.connectTCP(host, port, factory, bindAddress = bindaddress)

        return 1

    def setResult(self, result):
        self.results[result.host] = result

    def printResults(self):
        for r in self.results.values():
            print r


class MassExecOptions(usage.Options):

    synopsis = 'Usage: ' + os.path.basename(sys.argv[0]) + ' [options] host1 [host2 [host3...]]'

    optFlags = [
        ['log', 'v', 'Enable logging (defaults to stderr)'],
    ]

    optParameters = [
        ['user', 'u', None, 'The username to log in as on the remote host'],
        ['script', 's', None, 'The script file to copy and execute on remote host'],
        ['file', 'f', None, 'The additional file to copy to the remote host'],
        ['multiple', 'm', 10, 'The number of simultaneous connections', int],
        ['bind', 'b', None, 'The source address of the connections '],
    ]

    def __init__(self):
        usage.Options.__init__(self)
        self['files'] = []
        self['hosts'] = []

    def opt_file(self, file):
        self['files'].append(file)

    opt_f = opt_file

    def postOptions(self):
        if self['script'] is None:
            raise usage.UsageError("Missing script filename")

        if self['user'] is None:
            self['user'] = getpass.getuser()

    def parseArgs(self, *hosts):
        if len(hosts) == 0:
            raise usage.UsageError('Missing host(s)')
        self['hosts'].extend(hosts)


class SSHExecTransport(transport.SSHClientTransport):

    def verifyHostKey(self, hostKey, fingerprint):
        self.factory.setResultFingerprint(fingerprint)
        return defer.succeed(1)

    def connectionSecure(self):
        self.requestService(SSHExecUserAuth(self.factory.user, None, SSHExecConnection()))

    def connectionLost(self, reason):
        if self.service:
            self.service.serviceStopped()
        if hasattr(self, 'avatar'):
            self.logoutFunction()
        log.msg('connection lost')


class SSHExecAgentClient(agent.SSHAgentClient):

    def __init__(self):
        agent.SSHAgentClient.__init__(self)
        self.blobs = []

    def getPublicKeys(self):
        return self.requestIdentities().addCallback(self._cbPublicKeys)

    def _cbPublicKeys(self, blobcomm):
        log.msg('got %i public keys' % len(blobcomm))
        self.blobs = [x[0] for x in blobcomm]

    def getPublicKey(self):
        if self.blobs:
            return keys.Key.fromString(self.blobs.pop(0))
        return None


class SSHExecUserAuth(userauth.SSHUserAuthClient):

    preferredOrder = ['publickey']

    def __init__(self, user, options, *args):
        userauth.SSHUserAuthClient.__init__(self, user, *args)
        self.keyAgent = None
        self.options = options
        self.usedFiles = []

    def serviceStarted(self):
        log.msg('ssh-auth started')
        if 'SSH_AUTH_SOCK' in os.environ:
            cc = protocol.ClientCreator(reactor, SSHExecAgentClient)
            d = cc.connectUNIX(os.environ['SSH_AUTH_SOCK'])
            d.addCallback(self._setAgent)
            d.addErrback(self._ebSetAgent)
        else:
            userauth.SSHUserAuthClient.serviceStarted(self)

    def serviceStopped(self):
        log.msg('ssh-auth stopped')
        if self.keyAgent:
            self.keyAgent.transport.loseConnection()
            self.keyAgent = None

    def _setAgent(self, a):
        self.keyAgent = a
        d = self.keyAgent.getPublicKeys()
        d.addBoth(self._ebSetAgent)
        return d

    def _ebSetAgent(self, f):
        userauth.SSHUserAuthClient.serviceStarted(self)

    def getPublicKey(self):
        if self.keyAgent:
            key = self.keyAgent.getPublicKey()
            if key is not None:
                return key
        return None

    def signData(self, publicKey, signData):
        if not self.usedFiles:
            return self.keyAgent.signData(publicKey.blob(), signData)
        else:
            return userauth.SSHUserAuthClient.signData(self, publicKey, signData)

    def getPrivateKey(self):
        return None

    def ssh_USERAUTH_FAILURE(self, packet):
        canContinue, partial = common.getNS(packet)
        partial = ord(partial)
        if partial:
            self.authenticatedWith.append(self.lastAuth)

        canContinue = [meth for meth in canContinue.split(',')
                       if meth not in self.authenticatedWith]
        canContinue = [meth for meth in SSHExecUserAuth.preferredOrder
                       if meth in canContinue]

        log.msg('can continue with: %s' % canContinue)
        return self._cbUserauthFailure(None, iter(canContinue))


class SSHExecConnection(connection.SSHConnection):

    def serviceStarted(self):
        options = self.transport.factory.options
        self.files = [options['script']]
        self.files.extend(options['files'])
        self._sftp = defer.Deferred()
        ch = SFTPChannel(2**16, 2**15, self)
        self.openChannel(ch)
        self._sftp.addCallback(self._cbSFTP)
        self._sftp.addErrback(log.err, "Problem with SFTP transfer")

    def _cbSFTP(self, client):
        self.client = client
        self.runCopy(None)

    def runCopy(self, ignored):
        if len(self.files) == 0:
            self.runScript(None)
            return
        local = self.files.pop(0)
        remote = os.path.split(local)[1]
        log.msg('Copy', local)

        lperm = filepath.FilePath(local).getPermissions()
        permbit = 1
        rperm = 0
        for val in (lperm.other.execute, lperm.other.write, lperm.other.read,
                    lperm.group.execute, lperm.group.write, lperm.group.read,
                    lperm.user.execute, lperm.user.write, lperm.user.read):
            if val:
                rperm += permbit
            permbit *= 2

        lf = open(local, 'r')
        flags = filetransfer.FXF_WRITE|filetransfer.FXF_CREAT|filetransfer.FXF_TRUNC
        d = self.client.openFile(remote, flags, {'permissions': rperm})
        d.addCallback(self._cbPutOpenFile, lf)
        d.addErrback(self._ebCloseLf, lf)
        d.addErrback(lambda ignored: self.transport.loseConnection())
        return d

    def _cbPutOpenFile(self, rf, lf):
        numRequests = 5
        dList = []
        chunks = []
        for i in range(numRequests):
            d = self._cbPutWrite(None, rf, lf, chunks)
            if d:
                dList.append(d)
        dl = defer.DeferredList(dList, fireOnOneErrback=1)
        dl.addCallback(self._cbPutDone, rf, lf)
        dl.addCallbacks(self.runCopy)
        return dl

    def _cbPutWrite(self, ignored, rf, lf, chunks):
        chunk = self._getNextChunk(chunks)
        start, size = chunk
        lf.seek(start)
        data = lf.read(size)
        if data:
            d = rf.writeChunk(start, data)
            d.addCallback(self._cbPutWrite, rf, lf, chunks)
            return d
        else:
            return

    def _cbPutDone(self, ignored, rf, lf):
        lf.close()
        rf.close()
        log.msg('Copied {0}'.format(lf.name))

    def _ebCloseLf(self, f, lf):
        lf.close()
        return f

    def _getNextChunk(self, chunks):
        end = 0
        for chunk in chunks:
            if end == 'eof':
                return # nothing more to get
            if end != chunk[0]:
                i = chunks.index(chunk)
                chunks.insert(i, (end, chunk[0]))
                return (end, chunk[0] - end)
            end = chunk[1]
        bufSize = 32768
        chunks.append((end, end + bufSize))
        return (end, bufSize)

    def runScript(self, ignored):
        ch = ScriptChannel(2**16, 2**15, self)
        ch._close = defer.Deferred()
        ch._close.addCallback(self.runRemove)
        self.openChannel(ch)

    def runRemove(self, ignored):
        self.files = [options['script']]
        self.files.extend(options['files'])
        self._cbRemove(None)

    def _cbRemove(self, ignored):
        if len(self.files) == 0:
            self.transport.loseConnection()
            return
        local = self.files.pop(0)
        remote = os.path.split(local)[1]
        d = self.client.removeFile(remote)
        d.addCallback(self._cbRemove)
        d.addErrback(lambda ignored: self.transport.loseConnection())
        return d


class SFTPChannel(channel.SSHChannel):

    name = 'session'

    def channelOpen(self, ignored):
        d = self.conn.sendRequest(self, 'subsystem', common.NS('sftp'), wantReply = 1)
        d.addCallbacks(self._cbSFTP)
        #d.addErrback(_ebExit)

    def _cbSFTP(self, result):
        self.client = filetransfer.FileTransferClient()
        self.client.makeConnection(self)
        self.dataReceived = self.client.dataReceived
        self.conn._sftp.callback(self.client)


class ScriptChannel(channel.SSHChannel):

    name = 'session'

    def openFailed(self, reason):
        log.msg('channel open fail: {0}'.format(reason))

    def channelOpen(self, ignoredData):
        self.data = ''
        command = os.path.split(self.conn.transport.factory.options['script'])[1]
        command = os.path.join('.', command)
        self.conn.sendRequest(self, 'exec', common.NS(command), wantReply = 1)

    def request_exit_status(self, data):
        self.status = struct.unpack('>L', data)[0]
        self.conn.transport.factory.setResultStatus(self.status)
        self.loseConnection()

    def dataReceived(self, data):
        self.data += data

    def closed(self):
        self.conn.transport.factory.setResultOutput(self.data)
        self.loseConnection()
        self._close.callback('script')


class SSHExecResult:

    def __init__(self, host):
        self.host = host
        self.failure = None
        self.figerprint = None
        self.status = None
        self.output = None

    def __repr__(self):
        s = self.host + ': '
        if self.failure is not None:
            s += 'failure: ' + self.failure
        else:
            s += str(self.status) + ', ' + repr(self.output)
        return s


class SSHExecFactory(protocol.ClientFactory):

    protocol = SSHExecTransport

    def __init__(self, user, host, port, options, multiplestate):
        self.user = user
        self.host = host
        self.port = port
        self.options = options
        self.multiplestate = multiplestate
        self.result = SSHExecResult(host)

    def stopFactory(self):
        self.multiplestate.setResult(self.result)
        self.multiplestate.nextClient()

    def buildProtocol(self, address):
        return protocol.ClientFactory.buildProtocol(self, address)

    def clientConnectionFailed(self, connector, reason):
        self.result.failure = reason.getErrorMessage()

    def setResultFingerprint(self, fingerprint):
        self.result.fingerprint = fingerprint

    def setResultStatus(self, status):
        self.result.status = status

    def setResultOutput(self, output):
        self.result.output = output



if __name__ == '__main__':

    args = sys.argv[1:]

    options = MassExecOptions()

    try:
        options.parseOptions(args)
    except usage.UsageError, u:
        print >> sys.stderr, '{0}: {1}\n{2}'.format(
            os.path.basename(sys.argv[0]), u, options)
        sys.exit(1)

    if options['log']:
        log.startLogging(sys.stdout)

    state = MassExecMultiple(options)

    while state.nextClient(True):
        pass

    reactor.run()
