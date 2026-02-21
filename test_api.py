import requests
import json

files = {'file': open('sample.pdml', 'rb')}
res = requests.post('http://localhost:8080/api/upload', files=files)
session = res.json()['session_key']

res = requests.get(f'http://localhost:8080/api/packets?session={session}')
packets = res.json()['packets']
print(f"Total packets: {len(packets)}")
for p in packets:
    print(f"Frame {p['frame_num']}: protocols={p.get('protocols')}")
