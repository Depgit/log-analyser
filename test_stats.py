import urllib.request
import json
import uuid

# Create a small boundary for our multipart form
boundary = uuid.uuid4().hex

# Read the file
with open('sample.pdml', 'rb') as f:
    file_bytes = f.read()

# Build multipart body
body = (
    f"--{boundary}\r\n"
    f"Content-Disposition: form-data; name=\"file\"; filename=\"sample.pdml\"\r\n"
    f"Content-Type: application/octet-stream\r\n\r\n"
).encode('utf-8') + file_bytes + f"\r\n--{boundary}--\r\n".encode('utf-8')

req = urllib.request.Request("http://localhost:8080/api/upload", data=body)
req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
resp = urllib.request.urlopen(req)
session = json.loads(resp.read().decode('utf-8'))['session_key']

req2 = urllib.request.Request(f"http://localhost:8080/api/stats?session={session}")
resp2 = urllib.request.urlopen(req2)
stats = json.loads(resp2.read().decode('utf-8'))
print(json.dumps(stats['all_protocols_dist'], indent=2))
