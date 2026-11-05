"""Evaluate a locally installed clamd against a user-supplied labeled manifest.
Never executes samples. Uses the standard-library client; no malware downloads.
"""
import argparse, hashlib, json, pathlib, socket, struct, time

def ask(address, command):
    with socket.create_connection(address, timeout=3) as stream:
        stream.settimeout(30); stream.sendall(command)
        return receive(stream)

def receive(stream):
    data=bytearray()
    while len(data)<65536:
        chunk=stream.recv(1)
        if not chunk or chunk in (b'\0',b'\n'): break
        data.extend(chunk)
    else: raise ValueError('Response exceeds limit')
    return data.decode('utf-8',errors='replace')

def classify(reply):
    if reply.endswith(' FOUND'): return 'detected'
    if reply.endswith(' OK'): return 'no_known_match'
    return 'error'

def measure(rows):
    tp=fp=tn=fn=unknown=0
    for row in rows:
        if row['status']=='error': unknown+=1; continue
        detected=row['status']=='detected'
        if row['malicious'] and detected: tp+=1
        elif row['malicious']: fn+=1
        elif detected: fp+=1
        else: tn+=1
    return dict(true_positive=tp,false_positive=fp,true_negative=tn,false_negative=fn,unknown=unknown,
        precision=tp/(tp+fp) if tp+fp else None,recall_assessed=tp/(tp+fn) if tp+fn else None,
        assessment_coverage=(len(rows)-unknown)/len(rows) if rows else None,
        note='User-supplied labels; not independent certification. Errors are unknown, not negative detections.')

def scan(address,path,cap):
    with path.open('rb') as file, socket.create_connection(address,timeout=3) as stream:
        stream.settimeout(30);stream.sendall(b'zINSTREAM\0'); digest=hashlib.sha256(); size=0
        while chunk:=file.read(65536):
            size+=len(chunk)
            if size>cap: raise ValueError('File exceeds configured cap')
            digest.update(chunk);stream.sendall(struct.pack('!I',len(chunk))+chunk)
        stream.sendall(b'\0'*4);reply=receive(stream)
        return {'status':classify(reply),'response':reply,'sha256':digest.hexdigest()}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('manifest',type=pathlib.Path);parser.add_argument('--port',type=int,default=3310);parser.add_argument('--max-mib',type=int,default=128);args=parser.parse_args()
    cases=json.loads(args.manifest.read_text(encoding='utf-8'));assert isinstance(cases,list) and len(cases)<=10000
    address=('127.0.0.1',args.port);version=ask(address,b'zVERSION\0');rows=[]
    for case in cases:
        if type(case.get('malicious')) is not bool: raise ValueError('malicious must be a boolean')
        path=pathlib.Path(case['path']); path=path if path.is_absolute() else args.manifest.resolve().parent/path
        row={'path':str(path),'malicious':case['malicious']}
        try: row.update(scan(address,path,args.max_mib*1024*1024))
        except (OSError,ValueError) as error: row.update(status='error',error=str(error))
        rows.append(row)
    print(json.dumps({'engine_version':version,'timestamp':time.time(),'metrics':measure(rows),'results':rows},indent=2))
if __name__=='__main__': main()
