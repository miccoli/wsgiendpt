"""aws SNS endpoint"""

__version__ = "0.0.0"

import json
import base64
import urllib2
import logging

import OpenSSL


def headtoenv(key):
    """transforms header to HTTP_ environment variable"""
    return 'HTTP_' + key.upper().replace('-', '_')

#
# see http://docs.aws.amazon.com/sns/latest/dg/json-formats.html
#
AMZ_HEADERS = ('x-amz-sns-message-type', 'x-amz-sns-message-id',
               'x-amz-sns-topic-arn', 'x-amz-sns-subscription-arn', )
AMZ_OPT_HEADERS = ('x-amz-sns-rawdelivery', )
AMZ_ENVS = tuple(headtoenv(s) for s in AMZ_HEADERS + AMZ_OPT_HEADERS)
MESS_TYPES = ('Notification', 'SubscriptionConfirmation',
              'UnsubscribeConfirmation')

#
# signature verification
# see http://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.verify.signature.html
#

AMZ_SIG_MSG = {
    'Notification': ['Message', 'MessageId', 'Subject', 'Timestamp',
                     'TopicArn', 'Type'],
    'SubscriptionConfirmation': ['Message', 'MessageId', 'SubscribeURL',
                                 'Timestamp', 'Token', 'TopicArn', 'Type'],
    }
AMZ_SIG_MSG['UnsubscribeConfirmation'] = AMZ_SIG_MSG['SubscriptionConfirmation']
AMZ_SIG_MSG_OPT = ['Subject']


class Error(Exception):
    """local exception hierarchy root"""
    pass


class LogicError(Error):
    """exception to signal logic error"""
    pass


class SignatureError(Error):
    """exception raised if bad signature"""
    pass


def verifysig(data, cert, ):

    if not isinstance(cert, OpenSSL.crypto.X509):
        raise TypeError('%s not an X509 certificate')

    if data['SignatureVersion'] != '1':
        raise ValueError('unknown signature version')

    # get message signature
    sig = base64.b64decode(data['Signature'])

    # contruct message to sign
    mess = u''
    for key in AMZ_SIG_MSG[data['Type']]:
        if key not in data and key in AMZ_SIG_MSG_OPT:
            continue
        mess += key + '\n' + data[key] + '\n'

    # verify signature
    try:
        # FIXME: should infer message digest 'sha1' from PEM data.
        assert cert.get_signature_algorithm() == 'sha1WithRSAEncryption'
        OpenSSL.crypto.verify(cert, sig, mess.encode('utf-8'), 'sha1')
    except OpenSSL.crypto.Error as exp:
        raise SignatureError('%s' % exp)


class Application(object):
    """simple SNS endpoint"""

    #
    # http://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.html
    #

    allowed_meth = ('POST', )

    def __init__(self, ):

        self.logger = logging.getLogger(self.__module__)
        self.logger.debug("init %s", self)

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
            self.logger.error("method %s not allowed", env['REQUEST_METHOD'])
            raise LogicError(
                '405 Method not allowed', headers,
                'method %s not allowed' % env['REQUEST_METHOD'])

        # message headers
        for k in AMZ_HEADERS + AMZ_OPT_HEADERS:
            self.logger.debug("'%s' ->  '%s'", k, env.get(headtoenv(k)))

        for k in env:
            if k.startswith('HTTP_X_AMZ') and k not in AMZ_ENVS:
                self.logger.debug("UNKNOWN: '%s' ->  '%s'", k, env[k])

        try:
            amzhead = tuple(env[headtoenv(k)] for k in AMZ_HEADERS)
        except KeyError:
            self.logger.error("request does not appears to be a sns")
            raise LogicError('400 Bad Request', [], 'sorry?')

        if headtoenv('x-amz-sns-rawdelivery') in env:
            # log rawdata and return
            rawdata = env['wsgi.input'].read()
            self.logger.info("%s rawdata: %s", amzhead, rawdata)
        else:
            # decode json body
            try:
                data = json.load(env['wsgi.input'])
            except ValueError:
                self.logger.error("unable to decode json")
                raise LogicError('400 Bad Request', [], 'sorry?')

            assert (data['Type'], data['MessageId'], data['TopicArn'], ) == \
                amzhead[:3]
            assert env[headtoenv('x-amz-sns-subscription-arn')] not in \
                data.values()

            pem = urllib2.urlopen(data['SigningCertURL']).read()
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
            # except OpenSSL.crypto.Error as exp:
            # raise ValueError('invalid pem: %s' % exp.args)
            try:
                verifysig(data, cert, )
            except (ValueError, SignatureError) as exp:
                self.logger.error('Bad signature')
                self.logger.debug('Signature error: %s', exp)
                self.logger.debug('Bad Data: %s', data)
                raise LogicError('400 Bad Request', [], 'sorry?')

            self.logger.info("%s data: %s", amzhead, data)

        return
