import sys
import os
import argparse

from ide import app
from tlspktreader import readCaptureFile, printStats

# Run the server
if __name__ == "__main__":
    """
        TLS Analyzer starting point
    """

    print("""  ________   _____    __  __                __     __          __           ___                __                     
 /_  __/ /  / ___/   / / / /___ _____  ____/ /____/ /_  ____ _/ /_____     /   |  ____  ____ _/ /_  ______  ___  _____
  / / / /   \__ \   / /_/ / __ `/ __ \/ __  / ___/ __ \/ __ `/ //_/ _ \   / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 / / / /______/ /  / __  / /_/ / / / / /_/ (__  ) / / / /_/ / ,< /  __/  / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/_/ /_____/____/  /_/ /_/\__,_/_/ /_/\__,_/____/_/ /_/\__,_/_/|_|\___/  /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                                                             /____/                   
  """)

    # Flags
    parser = argparse.ArgumentParser(description='PCAP Pyshark reader')
    parser.add_argument('--ide', action=argparse.BooleanOptionalAction,
                        help='Whether or not to start the dash server (our IDE). If used, ignore other args.')
    parser.add_argument('--pcap', metavar='<pcap capture file>',
                        help='pcap file to parse')
    parser.add_argument('--tlskey', metavar='<tls key log file>',
                        help='key log file to decrypt tls messages')

    args = parser.parse_args()

    if args.ide:
        app.run_server(host="0.0.0.0", port=8050, debug=False)
    else:
        filename = args.pcap

        if not os.path.isfile(filename):
            print('"{}" does not exist.'.format(filename), file=sys.stderr)
        else:
            printStats(readCaptureFile(filename, args.tlskey))

        print("End of processing.")
