import csv,json,sys
S=sys.argv[1]; tune=set(json.load(open(S+'/tune-ids.json')))
def m(rows,pos):
    tp=sum(r['label']=='malicious' and pos(r) for r in rows); P=sum(r['label']=='malicious' for r in rows)
    fp=sum(r['label']=='benign' and pos(r) for r in rows); N=sum(r['label']=='benign' for r in rows)
    return f"attrapés {tp}/{P} ({100*tp/P:.0f} %)  faux positifs {fp}/{N} ({100*fp/N:.1f} %)"
for f in sys.argv[2:]:
    rows=list(csv.DictReader(open(f"{S}/{f}"),delimiter='\t'))
    for name,sub in [('entraînement',[r for r in rows if r['id'] in tune]),('test',[r for r in rows if r['id'] not in tune]),('tout',rows)]:
        print(f"{f:22} {name:13} ⛔ {m(sub,lambda r:r['verdict']=='block'):48} ⛔+⚠️ {m(sub,lambda r:r['verdict']!='ok')}")
    print()
