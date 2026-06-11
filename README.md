# http2-fuzz
HTTP2 web fuzzer made with native Python libraries. 

This tool works by cycling through HTTP/2 stream ID numbers to avoid terminating the TCP connection, allowing up to 32767 ((2**16)/2 - 1) requests being sent before a connection restart.

The stream ID number is rotated everytime the web server sends back a FRAME_RST frame, and the TCP connection resets everytime the web server sends back a FRAME_GOAWAY frame or the stream number limit is reached.

```
usage: http2fuzz.py [-h] [-v] [-t THREADS] [-i]
                    [-s STATUS_EQUALS | -sn STATUS_NOT_EQUALS | -cn CONTENT_LENGTH_NOT_EQUALS]
                    url wordlist

HTTP/2 Based Web Fuzzer Written In Python

positional arguments:
  url                   URL to fuzz (i.e., http://localhost)
  wordlist              Directory wordlist

options:
  -h, --help            show this help message and exit
  -v                    Enable debugging
  -t THREADS, --threads THREADS
                        Number of threads to run (default 64)

  -s STATUS_EQUALS      Status Code Equals (i.e., -s 200,201)
  -sn STATUS_NOT_EQUALS
                        Status Code Not Equals (i.e., -sn 404)
  -cn CONTENT_LENGTH_NOT_EQUALS
                        Content Length Not Equals (i.e., -cn 0)
```
