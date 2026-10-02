"""Bounded local input and fail-closed contract shared as source, no upstream calls."""
import base64, json, sys, pathlib, datetime, hashlib, os, stat, math
class ReviewError(ValueError): pass
def need(condition,message):
    if not condition: raise ReviewError(message)
def obj(v):
    need(isinstance(v,dict),"expected an object"); return v
def seq(v,limit=4096):
    need(isinstance(v,list) and len(v)<=limit,"invalid or excessive array"); return v
def string(v,limit=65536):
    need(isinstance(v,str) and len(v)<=limit,"invalid string")
    try:v.encode("utf-8")
    except UnicodeError:raise ReviewError("invalid UTF-8 string") from None
    return v
def integer(v,low=0,high=2**63-1):
    need(type(v) is int and low<=v<=high,"invalid integer"); return v
def boolean(v):
    need(type(v) is bool,"invalid boolean"); return v
def fields(v,required,optional=()):
    obj(v);need(set(required)<=set(v) and set(v)<=set(required)|set(optional),"missing or unsupported fields")
def b64(v,url=False,limit=4194304):
    s=string(v,limit*2)
    try:
        if url:
            need('=' not in s and all(c.isascii() and (c.isalnum() or c in '-_') for c in s),"invalid base64url")
            b=base64.b64decode(s+'='*((-len(s))%4),altchars=b'-_',validate=True)
            need(base64.urlsafe_b64encode(b).decode().rstrip('=')==s,"noncanonical base64url")
        else:
            b=base64.b64decode(s,validate=True)
            need(base64.b64encode(b).decode()==s,"noncanonical base64")
    except (ValueError,TypeError): raise ReviewError("invalid base64") from None
    need(len(b)<=limit,"decoded input too large");return b
def unique_pairs(pairs):
    d={}
    for k,v in pairs:
        need(k not in d,"duplicate JSON field");d[k]=v
    return d
def load(raw):
    need(len(raw)<=4194304,"input too large")
    try:d=json.loads(raw,object_pairs_hook=unique_pairs,parse_constant=lambda _: (_ for _ in ()).throw(ReviewError("nonfinite JSON number")))
    except (ValueError,UnicodeError,RecursionError): raise ReviewError("invalid JSON") from None
    def walk(v,depth=0):
        need(depth<=48,"input nesting limit")
        if isinstance(v,dict):
            need(len(v)<=4096,"object size limit")
            for key,x in v.items():string(key);walk(x,depth+1)
        elif isinstance(v,float):need(math.isfinite(v),"nonfinite JSON number")
        elif isinstance(v,str):string(v,4194304)
        elif isinstance(v,list):
            need(len(v)<=4096,"array size limit")
            for x in v:walk(x,depth+1)
    walk(d);return obj(d)
def instant(v):
    try:d=datetime.datetime.fromisoformat(string(v,64).replace('Z','+00:00'))
    except ValueError:raise ReviewError("invalid reference time") from None
    need(d.tzinfo is not None,"reference time must have timezone");return d.astimezone(datetime.timezone.utc)
def read(path,limit=4194304):
    path=string(path,4096)
    nofollow=getattr(os,"O_NOFOLLOW",None);nonblock=getattr(os,"O_NONBLOCK",None)
    need(type(nofollow) is int and nofollow>0 and type(nonblock) is int and nonblock>0,"safe local-file flags unavailable on this platform")
    fd=os.open(path,os.O_RDONLY|nofollow|nonblock)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode),"input must be a regular file");need(before.st_size<=limit,"file size limit")
        data=bytearray()
        while len(data)<=limit:
            block=os.read(fd,min(65536,limit+1-len(data)))
            if not block:break
            data.extend(block)
        after=os.fstat(fd)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"input changed during read")
        need(len(data)<=limit,"file size limit");return bytes(data)
    finally:os.close(fd)
def report(**kwargs):return {"status":"PASS","complete":True,**kwargs}
def main(audit):
    try:
        need(len(sys.argv)==2,"usage: command request.json (or - for stdin)")
        raw=sys.stdin.buffer.read(4194305) if sys.argv[1]=='-' else read(sys.argv[1])
        result=audit(load(raw))
    except ReviewError as e: result={"status":"FAIL","complete":False,"error":str(e)}
    except Exception: result={"status":"FAIL","complete":False,"error":"input invalid or unsupported; verification incomplete"}
    print(json.dumps(result,sort_keys=True,ensure_ascii=True))
    return 0 if result['status']=='PASS' else 2 if result['status']=='OPEN' else 1
