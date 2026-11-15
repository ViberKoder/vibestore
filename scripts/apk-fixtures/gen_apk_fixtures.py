"""
Synthetic APK/AAB fixtures for the APK engine tests (src/lib/scanners/apk.ts).

They reproduce the binary formats the analyser reads (Android binary XML,
DEX magic and string table, APK Signature Scheme v2 block, META-INF signature
files). They are NOT built by aapt2/apksigner, so they test the parser and the
rules, not compatibility with real tool output.

Usage: python3 gen_apk_fixtures.py <output-dir>
"""
import sys
import struct, zipfile, io, os
OUT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "out")
os.makedirs(OUT, exist_ok=True)

# ---- Android binary XML encoder (test fixtures only) ----
class Pool:
    def __init__(self): self.s=[]; self.i={}
    def idx(self, v):
        if v is None: return 0xFFFFFFFF
        if v not in self.i: self.i[v]=len(self.s); self.s.append(v)
        return self.i[v]
def enc_str(s):
    b=s.encode("utf8")
    return bytes([len(s)]) + bytes([len(b)]) + b + b"\0"
def axml(elements):
    """elements: list of ('start', tag, [(name, kind, value)]) or ('end', tag)"""
    pool=Pool()
    chunks=b""
    for ev in elements:
        if ev[0]=="start":
            _,tag,attrs=ev
            name=pool.idx(tag)
            body=b""
            for (an,kind,val) in attrs:
                nidx=pool.idx(an)
                if kind=="str":
                    raw=pool.idx(val); dt=0x03; data=pool.idx(val)
                elif kind=="int":
                    raw=0xFFFFFFFF; dt=0x10; data=val & 0xFFFFFFFF
                elif kind=="bool":
                    raw=0xFFFFFFFF; dt=0x12; data=0xFFFFFFFF if val else 0
                body+=struct.pack("<IIIHBBI",0xFFFFFFFF,nidx,raw,8,0,dt,data)
            hdr=struct.pack("<HHI",0x0102,16,16+20+len(body))+struct.pack("<II",1,0xFFFFFFFF)
            ext=struct.pack("<IIHHHHHH",0xFFFFFFFF,name,20,20,len(attrs),0,0,0)
            chunks+=hdr+ext+body
        else:
            name=pool.idx(ev[1])
            chunks+=struct.pack("<HHI",0x0103,16,24)+struct.pack("<II",1,0xFFFFFFFF)+struct.pack("<II",0xFFFFFFFF,name)
    # string pool
    strings=[enc_str(s) for s in pool.s]
    offs=[]; data=b""
    for b in strings: offs.append(len(data)); data+=b
    while len(data)%4: data+=b"\0"
    header_size=28
    strings_start=header_size+4*len(offs)
    pool_bytes=struct.pack("<HHIIIIII",0x0001,header_size,0,len(offs),0,0x100,strings_start,0)
    body=b"".join(struct.pack("<I",o) for o in offs)+data
    size=header_size+len(body)
    pool_chunk=struct.pack("<HHI",0x0001,header_size,size)+pool_bytes[8:]+body
    pool_chunk=pool_chunk[:4]+struct.pack("<I",size)+pool_chunk[8:]
    total=8+len(pool_chunk)+len(chunks)
    return struct.pack("<HHI",0x0003,8,total)+pool_chunk+chunks

def manifest(pkg, version_code, min_sdk, target_sdk, perms, app_attrs, components):
    el=[("start","manifest",[("package","str",pkg),("versionCode","int",version_code),("versionName","str","1.0.0")])]
    el.append(("start","uses-sdk",[("minSdkVersion","int",min_sdk),("targetSdkVersion","int",target_sdk)])); el.append(("end","uses-sdk"))
    for p in perms:
        el.append(("start","uses-permission",[("name","str",p)])); el.append(("end","uses-permission"))
    el.append(("start","application",app_attrs))
    for tag, attrs, filt in components:
        el.append(("start",tag,attrs))
        if filt:
            el.append(("start","intent-filter",[])); el.append(("start","action",[("name","str","android.intent.action.MAIN")])); el.append(("end","action")); el.append(("end","intent-filter"))
        el.append(("end",tag))
    el.append(("end","application")); el.append(("end","manifest"))
    return axml(el)

# ---- fake dex: real magic + descriptor strings (what the scanner reads) ----
def dex(strings):
    body=b"\0".join(s.encode() for s in strings)
    return b"dex\n035\0" + b"\0"*32 + body + b"\0"*64

# ---- APK signature scheme v2 block, inserted before the central directory ----
def sig_block(debug):
    value = b"\x00"*4 + (b"CN=Android Debug" if debug else b"CN=Release Team")
    pair = struct.pack("<I",0x7109871a) + value
    pairs = struct.pack("<Q",len(pair)) + pair
    block_size = len(pairs) + 8 + 16
    return struct.pack("<Q",block_size) + pairs + struct.pack("<Q",block_size) + b"APK Sig Block 42"

def make_apk(path, files, v2_debug=None, v1_cert=None):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,"w",zipfile.ZIP_DEFLATED) as z:
        for name,data in files.items():
            if isinstance(data,str): z.writestr(name,data)
            else: z.writestr(name,data)
        if v1_cert is not None:
            z.writestr("META-INF/CERT.RSA", v1_cert)
            z.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    raw=bytearray(buf.getvalue())
    if v2_debug is not None:
        eocd=len(raw)-22
        while raw[eocd:eocd+4]!=b"PK\x05\x06": eocd-=1
        cd=struct.unpack("<I",raw[eocd+16:eocd+20])[0]
        block=sig_block(v2_debug)
        raw=raw[:cd]+block+raw[cd:]
        eocd+=len(block)
        raw[eocd+16:eocd+20]=struct.pack("<I",cd+len(block))
    open(path,"wb").write(bytes(raw))
    return path

ELF = b"\x7fELF\x02\x01\x01" + b"\0"*64
PE = b"MZ" + b"\0"*58 + struct.pack("<I",0x80) + b"\0"*64 + b"PE\0\0" + b"\0"*200

# 1. deliberately bad package
bad_manifest = manifest("com.example.bad", 3, 16, 16,
    ["android.permission.INTERNET","android.permission.READ_SMS","android.permission.RECORD_AUDIO",
     "android.permission.SYSTEM_ALERT_WINDOW","android.permission.BIND_ACCESSIBILITY_SERVICE"],
    [("debuggable","bool",True),("allowBackup","bool",True),("usesCleartextTraffic","bool",True)],
    [("provider",[("name","str","com.example.bad.Leak"),("exported","bool",True),("grantUriPermissions","bool",True)],False),
     ("activity",[("name","str",".Main"),("exported","bool",True)],True)])
bad_dex = dex(["Ldalvik/system/DexClassLoader;","Ljava/lang/Runtime;","exec",
    "Landroid/accessibilityservice/AccessibilityService;","Landroid/telephony/SmsManager;",
    "https://discord.com/api/webhooks/123456/abcDEF","AKIAIOSFODNN7EXAMPLE"])
make_apk(f"{OUT}/bad.apk", {
    "AndroidManifest.xml": bad_manifest,
    "classes.dex": bad_dex,
    "lib/arm64-v8a/libjiagu.so": ELF,
    "assets/fake.png": PE,
    "assets/payload.apk": b"PK\x03\x04"+b"\0"*100,
}, v2_debug=True, v1_cert=b"Android Debug certificate bytes")

# 2. clean modern package
clean_manifest = manifest("com.example.clean", 12, 26, 35, ["android.permission.INTERNET"],
    [("allowBackup","bool",False)],
    [("activity",[("name","str",".Main"),("exported","bool",True)],True)])
make_apk(f"{OUT}/clean.apk", {
    "AndroidManifest.xml": clean_manifest,
    "classes.dex": dex(["Lcom/example/clean/Main;","https://api.example.com/v1/items"]),
    "lib/arm64-v8a/libclean.so": ELF,
}, v2_debug=False)

# 3. unsigned
make_apk(f"{OUT}/unsigned.apk", {"AndroidManifest.xml": clean_manifest, "classes.dex": dex(["x"])})

# 4. v1-only signature
make_apk(f"{OUT}/v1only.apk", {"AndroidManifest.xml": clean_manifest, "classes.dex": dex(["x"])}, v1_cert=b"Release cert bytes")

# 5. claims a well-known package name
brand_manifest = manifest("com.whatsapp", 1, 26, 35, ["android.permission.INTERNET"], [], [])
make_apk(f"{OUT}/brand.apk", {"AndroidManifest.xml": brand_manifest, "classes.dex": dex(["x"])}, v2_debug=False)

# 6. Android App Bundle layout (base module)
make_apk(f"{OUT}/bundle.aab", {
    "base/manifest/AndroidManifest.xml": clean_manifest,
    "base/dex/classes.dex": dex(["Lcom/example/clean/Main;"]),
    "base/lib/arm64-v8a/libclean.so": ELF,
})
print("generated", sorted(os.listdir(OUT)))
