"""Definitive oracle: does a candidate plaintext yield a private key for a
known GSMG target address? Pure-python secp256k1 + base58check (no deps)."""
import hashlib
from Crypto.Hash import RIPEMD160
def ripemd160(b):return RIPEMD160.new(b).digest()

P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
   0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def inv(a,m=P):return pow(a,m-2,m)
def add(p,q):
    if p is None:return q
    if q is None:return p
    if p[0]==q[0] and (p[1]+q[1])%P==0:return None
    if p==q:l=(3*p[0]*p[0])*inv(2*p[1])%P
    else:l=(q[1]-p[1])*inv((q[0]-p[0])%P)%P
    x=(l*l-p[0]-q[0])%P;y=(l*(p[0]-x)-p[1])%P;return(x,y)
def mul(k,p=G):
    r=None
    while k:
        if k&1:r=add(r,p)
        p=add(p,p);k>>=1
    return r
B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58c(b):
    n=int.from_bytes(b,'big');s=''
    while n:n,r=divmod(n,58);s=B58[r]+s
    return '1'*(len(b)-len(b.lstrip(b'\0')))+s
def addr(pub):
    h=ripemd160(hashlib.sha256(pub).digest())
    pre=b'\x00'+h;return b58c(pre+hashlib.sha256(hashlib.sha256(pre).digest()).digest()[:4])
def priv_to_addrs(k):
    if not(0<k<N):return []
    x,y=mul(k);out=[]
    comp=(b'\x02' if y%2==0 else b'\x03')+x.to_bytes(32,'big')
    unc=b'\x04'+x.to_bytes(32,'big')+y.to_bytes(32,'big')
    return [addr(comp),addr(unc)]
TARGETS={'1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe','1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu',
         '145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ'}
def check_bytes(pt):
    """scan every 32-byte window as a candidate raw private key."""
    hits=[]
    for i in range(0,max(1,len(pt)-31)):
        w=pt[i:i+32]
        if len(w)<32:break
        k=int.from_bytes(w,'big')
        for a in priv_to_addrs(k):
            if a in TARGETS:hits.append((i,a,w.hex()))
    # also try sha256(plaintext) as key
    k=int.from_bytes(hashlib.sha256(pt).digest(),'big')
    for a in priv_to_addrs(k):
        if a in TARGETS:hits.append(('sha256(pt)',a))
    return hits

def selftest():
    a=priv_to_addrs(1)
    assert a==['1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH','1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'],a
    print('btc_oracle self-test OK (priv=1 ->',a[0],'/',a[1],')')
    print('targets:',sorted(TARGETS))

if __name__=='__main__':
    selftest()
