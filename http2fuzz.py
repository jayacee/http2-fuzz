import socket
import ssl
import struct
import sys
import urllib.parse

from typing import Generator
import lib.huffman as huffman
import lib.http2 as http2

import threading
import argparse
import signal

import time

from os import system # Uses os.system("") to enable ANSI color codes on Windows


class debugger:
    def __init__(self,enabled=False):
        self.enabled = enabled

        self.attempted_files = 0

        self.info = 0x0
        self.warning = 0x1
        self.error = 0x2
        self.success = 0x3

        self.COLOR_ANSI_RESET = '\033[0m'

        self.terminate_thread = False

        # ANSI color codes
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\x1b[34m'

        self.debug_levels = {
            self.info:(BLUE,"INFO"),
            self.warning:(YELLOW,"WARNING"),
            self.error:(RED,"ERROR"),
            self.success:(GREEN,"SUCCESS")
            }

    def print_message(self,text,debug_type):
        if self.enabled or debug_type == self.error or debug_type == self.success:
            print(f"{self.debug_levels[debug_type][0]}[{self.debug_levels[debug_type][1]}] {text} {self.COLOR_ANSI_RESET}")
            
global_debugger = debugger()

class connection_handler:
    def __init__(self,ip,stream_id,wordlist_handle,print_criteria,port=80,ignore=False):
        self._hpack_decoder = huffman.HpackDecoder(max_table_size=http2.constants.CLIENT_SETTINGS[0x1])
        self.ip = ip
        self.port = port

        self.ignore = ignore

        self.print_criteria = print_criteria
        
        self.wordlist_handle = wordlist_handle
        self.extra_headers = {}

        self.stream_id = stream_id
        self.socket = None
    def make_connection(self,reset_stream=False):
        self.stream_id = 1
        if not reset_stream:
            host = self.ip
            try:
                sock  = socket.create_connection((self.ip, self.port), timeout=10)
            except socket.gaierror as e:
                global_debugger.print_message(f"[STREAM {self.stream_id}] SOCKET ERROR {e}",global_debugger.error)
                global_debugger.terminate_thread = True
                exit()
        else:
            sock = self.socket
        try:
            sock.sendall(http2.constants.CONNECTION_PREFACE)
            #print("SENT CONNECTION PREFACE")
            sock.sendall(http2.build_settings_frame(http2.constants.CLIENT_SETTINGS))
            #print("CLIENT_SETTINGS")
            sock.sendall(http2.build_window_update(0, 2 ** 24 - 65535))  # connection-level flow control
            #print("CONNECTION CONTROL")
            self.socket = sock
            return True
        except Exception as e:
            print(e)
            global_debugger.print_message(f"[STREAM {self.stream_id}] Unable to make connection",global_debugger.error)
            return False
    def check_print_criteria(self,data_response):
        status_code = data_response[0]
        # print(self.print_criteria)
        if self.print_criteria["status_codes"]:
            for target_status_code in self.print_criteria["status_codes"]:
                if status_code == int(target_status_code):
                    return True
            return False
        elif self.print_criteria["status_codes_not"]:
            for target_status_code in self.print_criteria["status_codes_not"].split(","):
                if status_code == int(target_status_code):
                    return False
            return True
        elif self.print_criteria["content_length_not"]:
            if len(data_response[2]) != target_status_code:
                return True
            else:
                return False
    def next_get_request(self,check_path):
        return http2.http2_get(self.socket,"/" + check_path,self.stream_id,self.ip,self._hpack_decoder)
        
    def thread_entry(self):
        self.make_connection()
        while (path_to_check := self.wordlist_handle.__next__().strip()):
            path_to_check = urllib.parse.quote(path_to_check)
            retry_word = True
            retry_count = 0
            while retry_word:
                retry_count += 1
                if retry_count > 2:
                    # Path causing an error, ignore
                    break
                retry_word = False
                if global_debugger.terminate_thread:
                    exit()
                    
                data = self.next_get_request(path_to_check)
                        
                if data[0] == -1: #FRAME_RST_STREAM
                    global_debugger.print_message(f"[STREAM {self.stream_id}] FRAME_RST received, incrementing stream...",global_debugger.warning)
                    self.stream_id += 2
                    #if self.ignore:
                    #    self.make_connection()
                    #else:
                    #    self.make_connection(reset_stream=True)
                    retry_word = True

                elif data[0] == -2: #FRAME_GOAWAY
                    global_debugger.print_message(f"[STREAM {self.stream_id}] FRAME_GOAWAY received, remaking connection...",global_debugger.warning)
                    self.make_connection()
                    retry_word = True
                    
                elif data[0] == -3: #CONNECTION_ERROR
                    global_debugger.print_message(f"[STREAM {self.stream_id}] Connection error when calling http2_get",global_debugger.warning)
                    self.make_connection()
                    retry_word = True

                elif data[0] == -5: #CONNECTION_ERROR
                    global_debugger.print_message(f"[STREAM {self.stream_id}] Unknown error when calling http2_get",global_debugger.error)
                    self.make_connection()
                    retry_word = True   

                else:
                    global_debugger.attempted_files += 1
                    should_print = self.check_print_criteria(data)
                    if should_print:
                        global_debugger.print_message(f"[STREAM {self.stream_id}] /{path_to_check} (Status Code: {data[0]} Content Length: {len(data[2])}",global_debugger.success)



class ThreadSafeFileIterator:
    def __init__(self, file_handle):
        self.file = file_handle
        self.lock = threading.Lock()

    def __iter__(self):
        return self

    def tell(self):
        return self.file.tell()

    def seek(self,loc):
        with self.lock:
            self.file.seek(loc)

    def __next__(self):
        # Ensure only one thread pulls a line from the file buffer at a time
        with self.lock:
            line = self.file.readline()
            return line.strip()

def main():
    system("") # Enables ANSI Color Codes
    

    parser = argparse.ArgumentParser(description="HTTP/2 Based Web Fuzzer Written In Python")
    
    parser.add_argument("url",type=str,help="URL to fuzz (i.e., http://localhost)")
    parser.add_argument("wordlist",type=str,help="Directory wordlist")
    
    parser.add_argument("-v",action="store_true",help="Enable debugging")

    parser.add_argument("-t","--threads",help="Number of threads to run (default 12)",default=12,type=int)

    parser.add_argument("-i",help="Ignore FRAME_RST frames and restart connection anyway (may lead to a faster time if server doesn't support keep-alive connections)",action="store_true")

    print_on = parser.add_mutually_exclusive_group()

    print_on.add_argument("-s",type=str, dest="status_equals", help="Status Code Equals (i.e., -s 200,201)",default=None)
    print_on.add_argument("-sn",type=str, dest="status_not_equals", help="Status Code Not Equals (i.e., -sn 404)",default=None)
    print_on.add_argument("-cn", type=int,dest="content_length_not_equals",help="Content Length Not Equals (i.e., -cn 0)",default=None)

    print_on.set_defaults(status_not_equals="404")

    args = parser.parse_args()

    print_criteria = {
        "status_codes":args.status_equals,
        "status_codes_not":args.status_not_equals,
        "content_length_not":args.content_length_not_equals,
        }
    parsed_url = urllib.parse.urlparse(args.url)

    ip_addr = parsed_url.hostname
    port = parsed_url.port
    if port == None:
        port = 80
    scheme = parsed_url.scheme
    if not scheme:
        global_debugger.print_message("Please specify a scheme before the IP address (i.e., http://)",global_debugger.error)
        exit()

    if scheme == "https":
        global_debugger.print_message("Currently does not support HTTPS/SSL",global_debugger.error)

    global_debugger.enabled = args.v
    
    odd_numbers = list(range(1, args.threads*2, 2))

    wordlist_handle = open(args.wordlist,'r')

    thread_array = []

    for thread_count in range(1,args.threads+1):
        stream_id = odd_numbers[thread_count-1]
        global_debugger.print_message(f"Starting thread {thread_count} for stream id {stream_id}",global_debugger.info)
    
        connection_manager = connection_handler(
            ip_addr,
            stream_id,
            ThreadSafeFileIterator(wordlist_handle),
            print_criteria,
            port=port,
            ignore=args.i
            )
        
        thread = threading.Thread(target=connection_manager.thread_entry)
        thread_array.append(thread)
        thread.start()
        
    seconds_elapsed = 0

    starting_time = time.time()
    try:
        print("Fuzzer started")
        print("Press enter for status or press Ctrl+C to exit")

        while True:
            input()
            seconds_elapsed = time.time() - starting_time
            print(f"{round(seconds_elapsed,1)} seconds elapsed; {round(global_debugger.attempted_files/seconds_elapsed,2)} files/s")

    except KeyboardInterrupt:
        pass
    global_debugger.terminate_thread = True
    exit()
        
if __name__ == "__main__":
    main()
