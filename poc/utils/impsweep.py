"""Walk every .py file under a directory and import it to check it loads cleanly."""
# Usage: from the poc/ directory, run `python3 utils/impsweep.py`
import os, subprocess, sys
files=[]
for dp,dn,fn in os.walk("."):
    if "__pycache__" in dp: continue
    for f in fn:
        if f.endswith(".py"): files.append(os.path.join(dp,f))
files.sort()
drv='import importlib.util as u,sys\np=sys.argv[1]\ns=u.spec_from_file_location("m",p)\nm=u.module_from_spec(s)\ns.loader.exec_module(m)\n'
WIRE=("ModuleNotFoundError","No module named","cannot import name","ImportError","FileNotFoundError","SyntaxError")
wiring=[]; ok=0; rt=0
for p in files:
    try: r=subprocess.run([sys.executable,"-c",drv,p],capture_output=True,timeout=40,cwd=".")
    except subprocess.TimeoutExpired: rt+=1; continue
    if r.returncode==0: ok+=1; continue
    err=r.stderr.decode("utf8","replace")
    if any(w in err for w in WIRE): wiring.append((p, err.strip().splitlines()[-1] if err.strip() else ""))
    else: rt+=1
print(f"TOTAL {len(files)}  CLEAN {ok}  WIRING_FAIL {len(wiring)}  runtime/lab {rt}")
for p,e in wiring: print("  FAIL",p,"::",e)
