# http2-fuzz
HTTP2 web fuzzer made with native Python libraries. Supports multithreading and HTTP2 multiplexing.

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
                        Number of threads to run (default 12)
  -i                    Ignore FRAME_RST frames and restart connection anyway (may lead to a faster time if server
                        doesn't support keep-alive connections)
  -s STATUS_EQUALS      Status Code Equals (i.e., -s 200,201)
  -sn STATUS_NOT_EQUALS
                        Status Code Not Equals (i.e., -sn 404)
  -cn CONTENT_LENGTH_NOT_EQUALS
                        Content Length Not Equals (i.e., -cn 0)
```
