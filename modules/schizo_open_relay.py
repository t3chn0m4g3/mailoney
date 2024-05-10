__author__ = '@botnet_hunter'
__author__ = '@referefref'

'''
Complete rewrite and refactor using asyncio and pylibemu
'''

import asyncio
import json
import os
import time
from datetime import datetime
import logging
import coloredlogs
import re  

try:
    from pylibemu import Emulator
except ImportError:
    print("pylibemu is not installed")
    exit(1)

# Setup logging
logger = logging.getLogger('MailoneyServer')
logger.setLevel(logging.DEBUG)

# Setup file handler
file_handler = logging.FileHandler('/var/log/mailoney/mailoney.log')
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Setup console handler with color
console_handler = logging.StreamHandler()
console_formatter = coloredlogs.ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

async def log_to_file(file_path, ip, port, data):
    with open(file_path, "a") as f:
        message = f"[{time.time()}][{ip}:{port}] {data}"
        logger.debug(f"Logging to file: {file_path} | {message}")
        f.write(message + "\n")

async def log_to_hpfeeds(hpc, channel, data):
    if hpc:
        message = data
        hpfchannel = hpc.channel_prefix + "." + channel
        hpc.publish(hpfchannel, message)
        logger.debug(f"Published to HPFeeds: {hpfchannel} | {data}")

async def process_packet_for_shellcode(hpc, packet, ip, port, fqdn):
    emulator = Emulator()
    offset = emulator.shellcode_getpc_test(packet)
    if offset >= 0:
        emulator.prepare(packet, offset)
        emulator.test()
        await log_to_file(f"/var/log/mailoney/shellcode.log", ip, port, "Detected shellcode")
        await log_to_file(f"/var/log/mailoney/shellcode.log", ip, port, emulator.emu_profile_output)
        await log_to_hpfeeds(hpc, "shellcode", json.dumps({
            "Timestamp": time.time(),
            "ServerName": fqdn,
            "SrcIP": ip,
            "SrcPort": port,
            "Shellcode": emulator.emu_profile_output
        }))

class SMTPServerProtocol:
    def __init__(self, fqdn, hpc=None):
        self.fqdn = fqdn
        self.hpc = hpc
        self.mailfrom = None
        self.rcpttos = []
        self.data = b''  # Store data as bytes
        self.state = 'COMMAND'
        self.peername = None
        self.greeting = False

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        self.peername = addr
        writer.write(f'220 {self.fqdn} ESMTP Exim 4.69 #1 Ready\r\n'.encode())
        await writer.drain()
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                # Directly work with bytes to handle non-text data properly
                if self.state == 'COMMAND':
                    decoded_data = data.decode().strip()
                    logger.info(f"Received command: {decoded_data}")
                    response = await self.process_command(decoded_data, writer)
                elif self.state == 'DATA':
                    # Append bytes directly to self.data
                    self.data += data
                    if data.strip() == b'.':
                        response = await self.process_data(writer)
                    else:
                        continue  # Continue receiving data until the end of data marker
                if response:
                    writer.write(response.encode() + b'\r\n')
                    await writer.drain()
        finally:
            writer.close()

    async def process_command(self, line, writer):
        if line == '':
            return '500 Error: bad syntax'
        command, *args = line.split(maxsplit=1)
        command = command.upper()
        handler = getattr(self, f'smtp_{command}', None)
        if not handler:
            return f'502 Error: command "{command}" not implemented'
        if args:
            return await handler(*args)
        return await handler()

    async def process_data(self, writer):
        # Now process self.data which contains the entire message data as bytes
        if self.data.endswith(b'\r\n.\r\n'):
            self.data = self.data[:-5]  # Strip ending sequence
        elif self.data.endswith(b'\n.\n'):
            self.data = self.data[:-3]  # Strip ending sequence

        await process_packet_for_shellcode(self.hpc, self.data, self.peername[0], self.peername[1], self.fqdn)
        await log_to_file("/var/log/mailoney/mail.log", self.peername[0], self.peername[1], self.data.decode(errors='replace'))
        self.data = b''
        self.state = 'COMMAND'
        return '250 Ok'

    async def smtp_HELO(self, arg):
        if not arg:
            return '501 Syntax: HELO hostname'
        if self.greeting:
            return '503 Duplicate HELO/EHLO'
        self.greeting = True
        return f'250 {self.fqdn}'

    async def smtp_EHLO(self, arg):
        if not arg:
            return '501 Syntax: EHLO hostname'
        if self.greeting:
            return '503 Duplicate HELO/EHLO'
        self.greeting = True
        return f'250-{self.fqdn} Hello {arg} [{self.peername[0]}]\r\n250-SIZE 52428800\r\n250 AUTH LOGIN PLAIN'

    async def smtp_NOOP(self, *args):
        return '250 Ok'

    async def smtp_QUIT(self, *args):
        return '221 Bye'

    async def smtp_AUTH(self, mechanism=''):
        if not mechanism:
            return '501 Syntax: AUTH mechanism'
        return '235 Authentication succeeded'

    async def smtp_MAIL(self, arg=''):
        if not arg:
            return '501 Syntax: MAIL FROM:<address>'
        address = self.__getaddr('FROM:', arg)
        if not address:
            return '501 Syntax: MAIL FROM:<address>'
        if self.mailfrom:
            return '503 Error: nested MAIL command'
        self.mailfrom = address
        return '250 Ok'

    async def smtp_RCPT(self, arg=''):
        if not arg:
            return '501 Syntax: RCPT TO: <address>'
        address = self.__getaddr('TO:', arg)
        if not address:
            return '501 Syntax: RCPT TO: <address>'
        self.rcpttos.append(address)
        return '250 Ok'

    async def smtp_RSET(self, *args):
        self.mailfrom = None
        self.rcpttos = []
        self.data = ''
        self.state = 'COMMAND'
        return '250 Ok'

    async def smtp_DATA(self, *args):
        if not self.rcpttos:
            return '503 Error: need RCPT command'
        self.state = 'DATA'
        return '354 End data with <CR><LF>.<CR><LF>'

    def __getaddr(self, keyword, arg):
        start = arg.find(':')
        if start != -1:
            address = arg[start + 1:].strip()
            if address.startswith('<') and address.endswith('>'):
                return address[1:-1]
        return None

async def main(bind_ip, bind_port, srvname, hpc):
    server = await asyncio.start_server(
        SMTPServerProtocol(srvname, hpc).handle_client, bind_ip, bind_port)
    addr = server.sockets[0].getsockname()
    logger.info(f'Serving on {addr}')
    async with server:
        await server.serve_forever()

def module(bind_ip, bind_port, srvname, hpc):
    asyncio.run(main(bind_ip, bind_port, srvname, hpc)))
    run()
