#!/usr/bin/env python3
"""Run actual CLI binaries against deterministic, offline curl fixtures."""
import json, os, pathlib, socket, struct, subprocess, sys, tempfile, threading, time

assert os.geteuid() != 0, 'test must run unprivileged'
assert os.environ.get('OUTER_NET') != os.readlink('/proc/self/ns/net'), 'isolated network required'
base,candidate=map(lambda x:pathlib.Path(x).resolve(),sys.argv[1:3])
# 24 eligible releases on the first raw page, 6 ineligible; second raw page
# contains only 1.x. A catalog of 24 eligible entries must have 5 picker pages.
rows=[]
for i in range(24): rows.append({'tag_name':f'v2.0.0-beta.{24-i}','prerelease':True,'draft':False})
for i in range(36): rows.append({'tag_name':f'1.8.{36-i}','prerelease':False,'draft':False})
with tempfile.TemporaryDirectory(prefix='release-rpc-') as tmp:
    work=pathlib.Path(tmp); mock=work/'bin'; mock.mkdir(); log=work/'calls'; data=work/'data'; data.mkdir()
    (work/'rows.json').write_text(json.dumps(rows))
    curl=mock/'curl'; curl.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys,urllib.parse
p=pathlib.Path(os.environ['FIXTURE_DIR']); url=sys.argv[-1]; u=urllib.parse.urlparse(url)
if u.scheme!='https' or u.netloc not in ('api.github.com','github.com'): sys.exit(22)
if u.netloc=='github.com':
 with (p/'calls').open('a') as f:f.write('ATOM\\n')
 sys.exit(22)
q=urllib.parse.parse_qs(u.query); page=int(q.get('page',['1'])[0]); count=int(q.get('per_page',['30'])[0]);
with (p/'calls').open('a') as f:f.write(f'REST {page} {count}\\n')
if os.environ.get('FIXTURE_MODE')=='offline': sys.exit(28)
rows=json.loads((p/'rows.json').read_text()); print(json.dumps(rows[(page-1)*count:page*count]))
'''); curl.chmod(0o700)
    env={**os.environ,'PATH':str(mock)+':'+os.environ['PATH'],'FIXTURE_DIR':str(work),'TACHYON_DATA_DIR':str(data),'TACHYON_ROOT':str(work/'root')}
    # Materialize the native default store, then route only bootstrap DNS to
    # a deterministic local responder. No public network is reachable.
    init=subprocess.run([str(candidate),'compile_config'],env=env,capture_output=True,text=True,timeout=20)
    assert init.returncode==0,init.stderr[-1000:]
    store_path=data/'tachyon.json'
    store=json.loads(store_path.read_text())
    store['settings']['bootstrap_dns_servers']=['127.0.0.1:15353']
    store_path.write_text(json.dumps(store))
    dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    dns.bind(('127.0.0.1',15353))
    dns.settimeout(0.2)
    stop=threading.Event()
    def serve_dns():
        while not stop.is_set():
            try: packet,peer=dns.recvfrom(512)
            except socket.timeout: continue
            except OSError: return
            if len(packet)<17: continue
            pos=12
            while pos<len(packet) and packet[pos]!=0:
                pos += 1 + packet[pos]
            if pos+5>len(packet): continue
            qtype=int.from_bytes(packet[pos+1:pos+3],'big')
            question=packet[12:pos+5]
            answer=b''
            answers=0
            if qtype==1:
                answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+bytes((127,0,0,1))
                answers=1
            header=packet[:2]+b'\x81\x80'+b'\x00\x01'+answers.to_bytes(2,'big')+b'\x00\x00\x00\x00'
            try: dns.sendto(header+question+answer,peer)
            except OSError: return
    dns_thread=threading.Thread(target=serve_dns,daemon=True)
    dns_thread.start()
    print('NATIVE_RPC_LOCAL_DNS_FIXTURE_PASS')
    def rpc(binary,page,repo='fixture/catalog',mode='online',count=5):
        e={**env,'TACHYON_RELEASE_REPO':repo,'FIXTURE_MODE':mode}
        p=subprocess.run([str(binary),'component_list_releases','tachyon',str(count),str(page)],env=e,capture_output=True,text=True,timeout=30)
        assert p.returncode==0,(p.returncode,p.stderr[-500:]);return json.loads(p.stdout)
    def calls():return log.read_text().splitlines() if log.exists() else []
    def tags(r):return [x['tag'] for x in r]
    expected=[x['tag_name'] for x in rows[:24]]
    assert tags(rpc(base,1,'fixture/baseline'))==expected[:5]
    old2=rpc(base,2,'fixture/baseline');assert isinstance(old2,list) and tags(old2)!=expected[5:10]
    print('BASELINE_REST_PAGE2_REGRESSION_REPRODUCED')
    log.write_text('')
    assert tags(rpc(candidate,1))==expected[:5]; assert calls()==['REST 1 30'],calls()
    for i in range(2,5): assert tags(rpc(candidate,i))==expected[(i-1)*5:i*5]
    assert calls()==['REST 1 30'],calls()
    print('NATIVE_RPC_PAGES_1_TO_4_ONE_FETCH_PASS')
    page5_started=time.monotonic()
    page5=rpc(candidate,5)
    page5_elapsed=time.monotonic()-page5_started
    print('NATIVE_RPC_PAGE5_ELAPSED_MS',int(page5_elapsed*1000))
    if not isinstance(page5,list):
        print('NATIVE_RPC_PAGE5_NON_ARRAY',json.dumps(page5,sort_keys=True))
        print('NATIVE_RPC_PAGE5_CALLS',json.dumps(calls()))
        raise AssertionError('candidate page 5 returned non-array')
    assert tags(page5)==expected[20:]
    assert page5_elapsed<4.0,page5_elapsed
    assert rpc(candidate,6)==[]
    print('NATIVE_RPC_PARTIAL_AND_EXHAUSTED_PASS')
    prior=len(calls());assert tags(rpc(candidate,1,'fixture/another-repo'))==expected[:5];assert len(calls())==prior+1
    print('NATIVE_RPC_REPOSITORY_CACHE_ISOLATION_PASS')
    # Unavailable later page must not be reported as a successful empty history.
    assert rpc(candidate,2,'fixture/offline','offline')=={'error':'release catalog page unavailable'}
    print('NATIVE_RPC_OFFLINE_NOT_EXHAUSTED_PASS')
    assert tags(rpc(candidate,1,'fixture/single',count=1))==expected[:1]
    prior=len(calls());assert tags(rpc(candidate,2,'fixture/single',count=1))==expected[1:2];assert len(calls())==prior+1
    print('NATIVE_RPC_SINGLE_ITEM_NO_PREFETCH_PASS')
print('NATIVE_RPC_QUALIFICATION_PASS')
stop.set()
dns.close()
