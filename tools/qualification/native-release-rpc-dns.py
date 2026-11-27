#!/usr/bin/env python3
"""Run actual CLI binaries against deterministic, offline curl fixtures."""
import json, os, pathlib, socket, struct, subprocess, sys, tempfile, threading, time

assert os.geteuid() != 0, 'test must run unprivileged'
assert os.environ.get('OUTER_NET') and os.environ['OUTER_NET'] != os.readlink('/proc/self/ns/net'), 'isolated network required'
assert {name for _, name in socket.if_nameindex()} == {'lo'}, 'unexpected network interface'
assert os.environ.get('OUTER_MNT') and os.environ['OUTER_MNT'] != os.readlink('/proc/self/ns/mnt'), 'isolated runtime mounts required'
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
if os.environ.get('FIXTURE_MODE')!='offline':
 expected='api.github.com:443:192.0.2.10'
 if '--resolve' not in sys.argv or expected not in sys.argv:
  with (p/'calls').open('a') as f:f.write('MISSING_NATIVE_DNS\\n')
  sys.exit(22)
with (p/'calls').open('a') as f:f.write(f'REST {page} {count}\\n')
if os.environ.get('FIXTURE_MODE')=='offline': sys.exit(28)
rows=json.loads((p/'rows.json').read_text()); print(json.dumps(rows[(page-1)*count:page*count]))
'''); curl.chmod(0o700)
    env={**os.environ,'PATH':str(mock)+':'+os.environ['PATH'],'FIXTURE_DIR':str(work),'TACHYON_DATA_DIR':str(data),'TACHYON_ROOT':str(work/'root')}
    # Initialize the synthetic store using the real binary, with the network isolated.
    init=subprocess.run([str(base),'compile_config'],env=env,capture_output=True,text=True,timeout=30)
    assert init.returncode==0,init.stderr[-1000:]
    store=data/'tachyon.json'
    assert store.is_file(), 'fixture store path missing'
    # Bootstrap DNS is part of the production fetch path, not curl. Provide
    # a deterministic local A record in the success scenario.
    dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    dns.bind(('127.0.0.1',0))
    dns_count=[0]
    def answer_dns():
        while True:
            try: q,peer=dns.recvfrom(1024)
            except OSError: return
            if len(q)<17: continue
            end=12
            while end<len(q) and q[end]:
                end+=q[end]+1
            if end+5>len(q): continue
            question=q[12:end+5]
            qtype=struct.unpack('!H',question[-4:-2])[0]
            rr=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('192.0.2.10') if qtype==1 else b''
            dns_count[0]+=1
            dns.sendto(q[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(rr)),0,0)+question+rr,peer)
    threading.Thread(target=answer_dns,daemon=True).start()
    config=json.loads(store.read_text())
    config['settings']['bootstrap_dns_servers']=[f'127.0.0.1:{dns.getsockname()[1]}']
    config['settings']['download_components_via_proxy']=False
    store.write_text(json.dumps(config))
    def rpc(binary,page,repo='fixture/catalog',mode='online',count=5):
        e={**env,'TACHYON_RELEASE_REPO':repo,'FIXTURE_MODE':mode}
        started=time.monotonic()
        p=subprocess.run([str(binary),'component_list_releases','tachyon',str(count),str(page)],env=e,capture_output=True,text=True,timeout=30)
        assert p.returncode==0,(p.returncode,p.stderr[-1000:])
        result=json.loads(p.stdout)
        print(f'RPC binary={binary.parent.parent.name} page={page} count={count} mode={mode} elapsed={time.monotonic()-started:.3f}s dns={dns_count[0]} result_type={type(result).__name__} size={len(result)} calls={calls()}',flush=True)
        return result
    def calls():return log.read_text().splitlines() if log.exists() else []
    def tags(r):
        assert isinstance(r,list),f'expected release array, got {r!r}'
        return [x['tag'] for x in r]
    expected=[x['tag_name'] for x in rows[:24]]
    assert tags(rpc(base,1,'fixture/baseline'))==expected[:5]
    assert dns_count[0]>0, 'native DNS response not exercised'
    old2=rpc(base,2,'fixture/baseline');assert isinstance(old2,list) and tags(old2)!=expected[5:10]
    print('BASELINE_REST_PAGE2_REGRESSION_REPRODUCED')
    log.write_text('')
    assert tags(rpc(candidate,1))==expected[:5]; assert calls()==['REST 1 30'],calls()
    for i in range(2,5): assert tags(rpc(candidate,i))==expected[(i-1)*5:i*5]
    assert calls()==['REST 1 30'],calls()
    print('NATIVE_RPC_PAGES_1_TO_4_ONE_FETCH_PASS')
    assert tags(rpc(candidate,5))==expected[20:]
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
    assert dns_count[0]>0,'native bootstrap DNS was not exercised'
    dns.close()
print('NATIVE_RPC_QUALIFICATION_PASS')
