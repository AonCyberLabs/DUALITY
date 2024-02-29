#!/usr/bin/env python3

#
# Copyright 2024 Aon plc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os, sys
import os.path, time
import urllib.request, urllib.parse, urllib.error
import html
import shutil
import mimetypes
import re
import os, sys
import os.path, time
from io import BytesIO
import argparse
import base64
import posixpath
import http.server
import socketserver

def format_bytes(bytes_num):
    'Return the given bytes as a human friendly KB, MB, GB, or TB string'
    bytes_float = float(bytes_num)
    kilobyte = 1024.0
    megabyte = kilobyte ** 2
    gigabyte = kilobyte ** 3
    terabyte = kilobyte ** 4

    if bytes_float < kilobyte:
        unit = 'Bytes' if bytes_float != 1 else 'Byte'
        return f'{bytes_float} {unit}'
    elif kilobyte <= bytes_float < megabyte:
        return f'{bytes_float/kilobyte:.2f} KB'
    elif megabyte <= bytes_float < gigabyte:
        return f'{bytes_float/megabyte:.2f} MB'
    elif gigabyte <= bytes_float < terabyte:
        return f'{bytes_float/gigabyte:.2f} GB'
    else:  # assuming bytes_num >= terabyte
        return f'{bytes_float/terabyte:.2f} TB'


class ReqHandler(http.server.BaseHTTPRequestHandler):
  
    def do_GET(self):
        f = self.handle_request_header()
        if f:
            self.copyfile(f, self.wfile)
            f.close()
 
    def do_HEAD(self):
        f = self.handle_request_header()
        if f:
            f.close()
 
    def do_POST(self):
        post_result, details = self.handle_file_upload()
        html_buffer = BytesIO()
        html_buffer.write(details.encode())
        html_buffer.write(("<br><br><a href=\"%s\">" % self.headers['referer']).encode())
        html_buffer.write("<strong>Success!</strong>".encode())
        content_length = html_buffer.tell()
        html_buffer.seek(0)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(content_length))
        self.end_headers()
        if html_buffer:
            self.copyfile(html_buffer, self.wfile)
            html_buffer.close()​

    def handle_file_upload(self):
        received_files = []   
        content_type_header = self.headers['content-type']
        if not content_type_header:
            return (False, "Missing boundary in Content-Type header")
        boundary_value = content_type_header.split("=")[1].encode()
        total_bytes_remaining = int(self.headers['content-length'])
        current_line = self.rfile.readline()
        total_bytes_remaining -= len(current_line)
        if boundary_value not in current_line:
            return (False, "Boundary not found at content start")
        while total_bytes_remaining > 0:
            current_line = self.rfile.readline()
            total_bytes_remaining -= len(current_line)
            filename_match = re.findall(r'Content-Disposition.*name="file"; filename="([^\/]*)"', current_line.decode())
            if not filename_match:
                return (False, "File name missing in content")
            file_path = self.convert_path(self.path)
            file_full_path = os.path.join(file_path, filename_match[0])
            current_line = self.rfile.readline()
            total_bytes_remaining -= len(current_line)
            current_line = self.rfile.readline()
            total_bytes_remaining -= len(current_line)
            try:
                file_stream = open(file_full_path, 'wb')
            except IOError:
                return (False, "<br><br>Unable to create file for writing.<br>Check write permissions.")
            else:
                with file_stream:                    
                    previous_line = self.rfile.readline()
                    total_bytes_remaining -= len(previous_line)
                    while total_bytes_remaining > 0:
                        current_line = self.rfile.readline()
                        total_bytes_remaining -= len(current_line)
                        if boundary_value in current_line:
                            previous_line = previous_line[0:-1]
                            if previous_line.endswith(b'\r'):
                                previous_line = previous_line[0:-1]
                            file_stream.write(previous_line)
                            received_files.append(file_full_path)
                            break
                        else:
                            file_stream.write(previous_line)
                            previous_line = current_line
        return (True, "<br><br>'%s'" % "'<br>'".join(received_files))
 
    def handle_request_header(self):
        requested_path = self.convert_path(self.path)
        file_stream = None
        if os.path.isdir(requested_path):
            if not self.path.endswith('/'):
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index_file in ["index.html", "index.htm"]:
                potential_index = os.path.join(requested_path, index_file)
                if os.path.exists(potential_index):
                    requested_path = potential_index
                    break
            else:
                return self.display_directory_listing(requested_path)
        content_type = self.determine_content_type(requested_path)
        try:
            file_stream = open(requested_path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", content_type)
        file_stats = os.fstat(file_stream.fileno())
        self.send_header("Content-Length", str(file_stats.st_size))
        self.send_header("Last-Modified", self.date_time_string(file_stats.st_mtime))
        self.end_headers()
        return file_stream
 
    def display_directory_listing(self, path):
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "404")
            return None
        enc = sys.getfilesystemencoding()
        list.sort(key=lambda a: a.lower())
        f = BytesIO()
        displaypath = html.escape(urllib.parse.unquote(self.path))
        f.write(b'<html>\n')
        f.write(('<meta http-equiv="Content-Type" '
                 'content="text/html; charset=%s">' % enc).encode(enc))
        f.write(b"<hr>\n")
        f.write(b"<form ENCTYPE=\"multipart/form-data\" method=\"post\">")
        f.write(b"<input name=\"file\" type=\"file\" multiple/>")
        f.write(b"<input type=\"submit\" value=\"upload\"/></form>\n")
        f.write(b"<hr>\n")
        f.write(b'<table>\n')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            fsize = format_bytes(os.path.getsize(fullname))
            created_date = time.ctime(os.path.getctime(fullname))
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
                fsize = ''
                created_date = ''
            f.write(('<tr><td><a href="%s">%s</a></td></tr>\n'
                    % ( urllib.parse.quote(linkname), html.escape(displayname) )).encode(enc))
        f.write(b"</table><hr>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def convert_path(self, input_path):
        # Remove query parameters and fragment identifiers
        cleaned_path = input_path.split('?', 1)[0]
        cleaned_path = cleaned_path.split('#', 1)[0]
        # Normalize the path
        normalized_path = posixpath.normpath(urllib.parse.unquote(cleaned_path))
        path_segments = normalized_path.split('/')
        # Filter out empty segments
        filtered_segments = [segment for segment in path_segments if segment]
        # Start from the current working directory
        resolved_path = os.getcwd()
        for segment in filtered_segments:
            # Ignore current and parent directory references
            if segment in (os.curdir, os.pardir): continue
            # Join the path segments
            resolved_path = os.path.join(resolved_path, segment)
        return resolved_path
 
    def copyfile(self, source, outputfile):
        shutil.copyfileobj(source, outputfile)
 
    def determine_content_type(self, file_path):
        filename_root, file_extension = posixpath.splitext(file_path)
        # Convert extension to lowercase for consistency
        lower_extension = file_extension.lower()
        # Check if the extension is in the mapping
        if lower_extension in self.extensions_map:
            return self.extensions_map[lower_extension]
        # If no specific match, return the default type
        return self.extensions_map.get('', 'application/octet-stream')

 
    if not mimetypes.inited:
        mimetypes.init() 
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream',
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        })
 
parser = argparse.ArgumentParser()
parser.add_argument('--bind', '-b', default='', metavar='ADDRESS',
                        help='alternate bind address '
                             '[default: bind to all interfaces]')
parser.add_argument('port', action='store',
                        default=8080, type=int,
                        nargs='?',
                        help='Specify alternate port [default: 8080]')
args = parser.parse_args()

PORT = args.port
BIND = args.bind
HOST = BIND

if HOST == '':
	HOST = 'localhost'

Handler = ReqHandler

with socketserver.TCPServer((BIND, PORT), Handler) as httpd:
	serve_message = "Serving HTTP on {host} port {port} (http://{host}:{port}/) ..."
	print(serve_message.format(host=HOST, port=PORT))
	httpd.serve_forever()
