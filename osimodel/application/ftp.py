#
# ./osimodel/application/ftp.py
# Eduardo Banderas Alba
# 2022-08
#
from osimodel.layer                   import *
from utils.utils                      import tohex


class ftp(ApplicationLayer):

  __client_commands = [
    'USER',  # This command sends the user identification to the server.
    'PASS',  # This command sends the user password to the server.
    'CWD',   # This command allows the user to work with a different directory or dataset for file storage or retrieval without altering his login or accounting information.
    'RMD',   # This command causes the directory specified in the path name to be removed as a directory.
    'MKD',   # This command causes the directory specified in the pathname to be created as a directory.
    'PWD',   # This command causes the name of the current working directory to be returned in the reply.
    'RETR',  # This command causes the remote host to initiate a data connection and to send the requested file over the data connection.
    'STOR',  # This command causes to store of a file into the current directory of the remote host.
    'LIST',  # Sends a request to display the list of all the files present in the directory.
    'ABOR',  # This command tells the server to abort the previous FTP service command and any associated transfer of data.
    'QUIT'   # This command terminates a USER and if file transfer is not in progress, the server closes the control connection.
  ]

  __server_response = {
    200: 'Command okay',
    530: 'Not logged in',
    331: 'User name okay, need a password',
    225: 'Data connection open; no transfer in progress',
    221: 'Service closing control connection',
    551: 'Requested action aborted: page type unknown',
    502: 'Command not implemented',
    503: 'Bad sequence of commands',
    504: 'Command not implemented for that parameter'
  }

  def format():
    def fget(self):
      msg = f'{self.pktdata.decode().rstrip()}'

      if not self.verbose:
        msg = ''
        if self.dst == 21 or self.src == 21:  # control
          try:
            command, data = self.pktdata.decode().rstrip().split(' ', maxsplit=1)
          except:
            command = self.pktdata.decode().rstrip()

          filters = self.filter.get('ftp')
          for filter in filters.split(','):
            if command.upper() == filter.rstrip().upper():
              msg += f'{self.pktdata.decode().rstrip()} '

        if self.src == 20:   # data
          msg += f'{self.pktdata.decode().rstrip()} '

      return f'{msg.rstrip()}'

    return locals()

  format = property(**format())
#class ftp
