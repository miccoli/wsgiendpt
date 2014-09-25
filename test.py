import logging
import wsgiendpt
from waitress import serve

from wsgiref.validate import validator

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)

# serve(validator(wsgiendpt.Application()), host='127.0.0.1', port='8080')
serve(validator(wsgiendpt.Application()), unix_socket='/tmp/wait', 
                unix_socket_perms='666')

