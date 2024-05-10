__author__ = '@awhitehatter'
__author__ = '@referefref'

'''
Open relay module, will dump emails into a message log file

Thanks to:
https://djangosnippets.org/snippets/96/
https://muffinresearch.co.uk/fake-smtp-server-with-python/ (@muffinresearch)
'''

import asyncio
import os
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message

class OpenRelayHandler(Message):
    async def handle_DATA(self, server, session, envelope):
        peer = session.peer
        mailfrom = envelope.mail_from
        rcpttos = envelope.rcpt_tos
        data = envelope.content.decode('utf8', errors='replace')

        # Setup the Log File
        log_file_path = 'logs/mail.log'
        if not os.path.exists(log_file_path):
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        with open(log_file_path, 'a') as logfile:
            logfile.write('\n\n' + '*' * 50 + '\n')
            logfile.write('IP Address: {}\n'.format(peer[0]))
            logfile.write('Mail from: {}\n'.format(mailfrom))
            for recipient in rcpttos:
                logfile.write('Mail to: {}\n'.format(recipient))
            logfile.write('Data:\n{}\n'.format(data))
        return '250 Message accepted for delivery'

def run():
    sys.path.append("../")
    import mailoney
    controller = Controller(OpenRelayHandler(), hostname=mailoney.bind_ip, port=mailoney.bind_port)
    controller.start()
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print('Detected interruption, terminating...')
        controller.stop()

if __name__ == '__main__':
    run()
