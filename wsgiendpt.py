"""aws SNS endpoint"""

__version__ = "0.0.0"

import json
import base64
import urllib2
import logging

import OpenSSL

def headtoenv(key):
    """transforms header to HTTP_ environment variable"""
    return 'HTTP_' + key.upper().replace('-','_')

#
# see http://docs.aws.amazon.com/sns/latest/dg/json-formats.html
#
AMZ_HEADERS = ('x-amz-sns-message-type', 'x-amz-sns-message-id',
    'x-amz-sns-topic-arn', 'x-amz-sns-subscription-arn', )
AMZ_OPT_HEADERS = ('x-amz-sns-rawdelivery', )
AMZ_ENVS = tuple(headtoenv(s) for s in AMZ_HEADERS + AMZ_OPT_HEADERS)
MESS_TYPES = ('Notification', 'SubscriptionConfirmation', 
    'UnsubscribeConfirmation')


class Error(Exception):
    """local exception hierarchy root"""
    pass


class LogicError(Error):
    """exception to signal logic error"""
    pass


class Application(object):
    """simple SNS endpoint"""

    #
    # http://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.html
    #

    allowed_meth = ('POST', )

    keys = {
            'Notification': 
                ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 
                 'Type'],
             'SubscriptionConfirmation':
                ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 
                 'TopicArn', 'Type'], 
            }
    keys['UnsubscribeConfirmation'] = keys['SubscriptionConfirmation']
    optkeys = ['Subject']

    def __init__(self, ):

        self.logger = logging.getLogger(self.__module__)
        self.logger.debug("wsgi application %s", self)

    def __call__(self, environ, start_response):
        headers = []
        try:
            self.logic(environ)
        except LogicError as loerr:
            status, lohead, message = loerr.args
            self.logger.debug("LogicError: %s, %s", status, message)
            headers.extend(lohead)
            assert isinstance(message, str)
            headers.append(("Content-Type", "text/plain; charset=UTF-8"))
            message += '\n'
            resp_bytes = message.encode("UTF-8")
        else:
            status = '204 No Content'
            resp_bytes = ''

        headers.append(("Content-Length", str(len(resp_bytes))))
        start_response(status, headers)
        return (resp_bytes, )


    def logic(self, env):

        if env['REQUEST_METHOD'] not in self.allowed_meth:
            headers = [('Allow', ', '.join(self.allowed_meth))]
            raise LogicError('405 Method not allowed', headers, 
                'method %s not allowed' % env['REQUEST_METHOD'])

        for k in AMZ_HEADERS + AMZ_OPT_HEADERS:
            self.logger.debug("'%s' ->  '%s'", k, env.get(headtoenv(k)))

        for k in env:
            if k.startswith('HTTP_X_AMZ') and k not in AMZ_ENVS:
                self.logger.debug("UNKNOWN: '%s' ->  '%s'", k, env[k])

        for k in AMZ_HEADERS:
            if headtoenv(k) not in env:
                self.logger.error("request does not appears to be a sns")
                raise LogicError('400 Bad Request', [], 'sorry?')

        if headtoenv('x-amz-sns-rawdelivery') in env:
            self.logger.error("raw messages not accepted")
            raise LogicError('400 Bad Request', [], 'sorry?')

        # decode metadata
        try:
            metadata = json.load(env['wsgi.input'])
        except ValueError:
            raise LogicError('400 Bad Request', [], 'sorry?')

        self.logger.info("metadata: %s", metadata)

        # verify signature
        if metadata['SignatureVersion'] == '1':
            pem = urllib2.urlopen(metadata['SigningCertURL']).read()
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, 
                   pem)
            sig = base64.b64decode(metadata['Signature'])
            # contruct message to sign
            mess = u''
            for key in self.keys[metadata['Type']]:
                if key not in metadata and key in self.optkeys:
                    continue
                mess += key + '\n' + metadata[key] + '\n' 
            try:
                OpenSSL.crypto.verify(cert, sig, mess.encode('utf-8'), 'sha1')
            except OpenSSL.crypto.Error as exp:
                self.logger.error('Bad signature: %s', exp)
            else:
                self.logger.info('Good signature')
        else:
            self.logger.info('Unable to check signature')

