"""Replace only the two reviewed 140 releases, with private byte backups and rollback."""
import base64,hashlib,json,os,re,subprocess,sys,tempfile,urllib.error,urllib.parse,urllib.request
from pathlib import Path

REPO='CyberfiTechh/CyberFi-Releases';VERSION='0.0.140';SOURCE='83c8c27a4c8f88c375632739303a31bc2ab022fb'
TARGETS={446902538:'windows-v0.0.140',446881539:'mac-v0.0.140'}
PAYLOADS={446902538:['CyberFi-0.0.140-x64.exe'],446881539:['CyberFi-0.0.140-x64.dmg','CyberFi-0.0.140-arm64.dmg']}
PUBLIC_KEY='-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA09ZxJMbpq1uFEnz7n52M\nAJtceCXVQCo57lgwMAmizgJaGVGsgsMpzqgCCRgXBN+bPygE+16S9XwYOwHDlnNG\noq8h+bE9Nxce3PzsQHrscdHTT1lGQ/5XwSmvzTvxLdURtQWpaXZl7lJghUnZHNDA\n8SOHbk8rQ+butE82lhcq0C+hgJgHTUqFl9Irppi2O+MpufsZo8PX5jphD4H0aX0k\nB9P+LUreoBmG/L3T3AMZEzQZG606awc/ZMYsJcJkt4xNMjR3ZMz1aWKErW2AXDeY\nyfAo0zmEAUEAFSc3UEJRnmBAjorVA3C/rHJzYP7QabSh8ORLOUrqQYgqCpTLETpf\nct0J+NphCLuBGNQ5IeId5IPiBNZlKynGzP/HK+oJTvJ31hTHIiaA+5pfIESXELIZ\nJ5awYGW0y7fii0CqRGwFMJnU829APVvAC9LJUzSSz7NP+2rmc/boYInx8cjN2/LO\nLI9HsPvON+oxM4MhjRxDd4CVoKDpI+rB2TthSdfxt3UxAgMBAAE=\n-----END PUBLIC KEY-----'
digest=lambda data:hashlib.sha256(data).hexdigest()

def asset_pin(a):return {k:a[k] for k in ['id','name','size','digest','state']}
def snapshot(r):
 return {**{k:r[k] for k in ['id','tag_name','target_commitish','name','body','draft','prerelease']},'assets':sorted([asset_pin(a) for a in r['assets']],key=lambda a:a['name'])}
def require_asset(a):
 assert type(a['id']) is int and a['id']>0
 assert isinstance(a['name'],str) and len(a['name'])<=180 and re.fullmatch(r'[A-Za-z0-9._-]+',a['name'])
 assert type(a['size']) is int and 0<a['size']<=512*1024**2
 assert re.fullmatch(r'sha256:[a-f0-9]{64}',a['digest'])

def validate(plan):
 assert plan['version']==VERSION and plan['sourceCommit']==SOURCE and plan['sourceGuardVerifiedByParent'] is True
 assert isinstance(plan['sourceGuardCheckedAt'],str) and plan['sourceGuardCheckedAt']
 assert len(plan['targets'])==2 and {t['releaseId'] for t in plan['targets']}==set(TARGETS)
 for t in plan['targets']:
  rid=t['releaseId'];assert t['tag']==TARGETS[rid];old=t['oldSnapshot']
  assert old['id']==rid and old['tag_name']==TARGETS[rid] and old['draft'] is False and old['prerelease'] is False
  assert re.fullmatch(r'[a-f0-9]{40}',old['target_commitish'])
  canonical={p+s for p in PAYLOADS[rid] for s in ['', '.sha256','.update.json']}
  oldnames={a['name'] for a in old['assets']};assert canonical.issubset(oldnames)
  assert oldnames.issubset(canonical|{p+'.report.json' for p in PAYLOADS[rid]})
  assert len(oldnames)==len(old['assets']) and len({a['id'] for a in old['assets']})==len(old['assets'])
  for a in old['assets']:require_asset(a);assert a['state']=='uploaded'
  assert len(t['newAssets'])==len(canonical) and {a['name'] for a in t['newAssets']}==canonical
  assert len({a['id'] for a in t['newAssets']})==len(t['newAssets'])
  for a in t['newAssets']:require_asset(a);assert type(a['sourceReleaseId']) is int and a['sourceReleaseId'] not in TARGETS and a['sourceReleaseId']>0
  assert isinstance(t['newBody'],str) and 0<len(t['newBody'])<=60000
 return plan

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args):return None
class GitHub:
 def __init__(self):
  self.token=os.environ['GH_TOKEN'];self.opener=urllib.request.build_opener(NoRedirect)
 def request(self,path,method='GET',data=None,accept='application/vnd.github+json'):
  assert path.startswith(REPO+'/') or path==REPO
  return urllib.request.Request('https://api.github.com/repos/'+path,method=method,headers={'Authorization':'Bearer '+self.token,'Accept':accept,'Content-Type':'application/json','User-Agent':'CyberFi-reviewed-140-correction'},data=None if data is None else json.dumps(data,ensure_ascii=False).encode())
 def api(self,path,method='GET',data=None):
  with self.opener.open(self.request(path,method,data),timeout=120) as response:
   if response.status==204:return None
   raw=response.read(8*1024**2+1);assert len(raw)<=8*1024**2;return json.loads(raw)
 def inventory(self):
  result={};page=1
  while True:
   rows=self.api(REPO+'/releases?per_page=100&page='+str(page));assert isinstance(rows,list) and len(rows)<=100
   result.update({r['id']:snapshot(r) for r in rows});assert len(result)<=5000
   if len(rows)<100:return result
   page+=1
 def download(self,a,file):
  require_asset(a)
  try:response=self.opener.open(self.request(REPO+'/releases/assets/'+str(a['id']),accept='application/octet-stream'),timeout=120)
  except urllib.error.HTTPError as e:
   if e.code!=302:raise
   location=e.headers['Location'];url=urllib.parse.urlsplit(location)
   assert url.scheme=='https' and url.hostname and not url.username and not url.password and url.port in (None,443)
   assert url.hostname.endswith('.githubusercontent.com') or url.hostname.endswith('.blob.core.windows.net')
   response=urllib.request.urlopen(location,timeout=120)
  h=hashlib.sha256();total=0
  with response as stream,file.open('xb') as out:
   while chunk:=stream.read(1024**2):
    total+=len(chunk);assert total<=a['size'];h.update(chunk);out.write(chunk)
  assert total==a['size'] and 'sha256:'+h.hexdigest()==a['digest']
 def upload(self,rid,a,file):
  require_asset(a);assert file.stat().st_size==a['size']
  request=urllib.request.Request('https://uploads.github.com/repos/'+REPO+'/releases/'+str(rid)+'/assets?name='+urllib.parse.quote(a['name']),method='POST',headers={'Authorization':'Bearer '+self.token,'Accept':'application/vnd.github+json','Content-Type':'application/octet-stream','User-Agent':'CyberFi-reviewed-140-correction'})
  with file.open('rb') as stream:
   request.data=stream;request.add_header('Content-Length',str(a['size']))
   with self.opener.open(request,timeout=300) as response:value=json.load(response)
  assert all(value[k]==a[k] for k in ['name','size','digest']) and value['state']=='uploaded';return asset_pin(value)

def signatures(target,folder):
 byname={a['name']:a for a in target['newAssets']};key=folder/'public.pem';key.write_text(PUBLIC_KEY)
 for name in PAYLOADS[target['releaseId']]:
  package=byname[name];manifest=json.loads((folder/(name+'.update.json')).read_text())
  assert set(manifest)=={'sha256','size','signature'} and manifest['sha256']==package['digest'][7:] and type(manifest['size']) is int and manifest['size']==package['size']
  assert (folder/(name+'.sha256')).read_text().strip()==manifest['sha256']+'  '+name
  signature=base64.b64decode(manifest['signature'],validate=True);assert len(signature)==384
  sig=folder/'signature.bin';body=folder/'signed-body.txt';sig.write_bytes(signature);body.write_bytes(f"{VERSION}\n{name}\n{manifest['sha256']}\n{manifest['size']}\n".encode())
  checked=subprocess.run(['openssl','dgst','-sha256','-verify',str(key),'-signature',str(sig),str(body)],capture_output=True,timeout=20);assert checked.returncode==0,'Pinned RSA verification failed: '+name

def promote(g,plan,root,report_path):
 validate(plan);before=g.inventory();report={'version':VERSION,'sourceCommit':SOURCE,'sourceGuardPerformedInCI':False,'sourceGuardVerifiedByParent':True,'sourceGuardCheckedAt':plan['sourceGuardCheckedAt'],'publicMutationStarted':False,'backupReleases':[],'published':[]}
 def save():report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 save();folders={}
 for t in plan['targets']:
  rid=t['releaseId'];assert snapshot(g.api(REPO+'/releases/'+str(rid)))==t['oldSnapshot'];folder=root/str(rid);folder.mkdir();old=folder/'old';new=folder/'new';old.mkdir();new.mkdir();folders[rid]=(old,new)
  for a in t['newAssets']:
   staging=g.api(REPO+'/releases/'+str(a['sourceReleaseId']));assert staging['draft'] is True
   actual=next(x for x in staging['assets'] if x['id']==a['id']);assert actual['state']=='uploaded' and all(actual[k]==a[k] for k in ['name','size','digest']);g.download(a,new/a['name'])
  signatures(t,new)
  for a in t['oldSnapshot']['assets']:g.download(a,old/a['name'])
 # Every byte needed for replacement or recovery exists locally before the first backup or public write.
 for t in plan['targets']:
  rid=t['releaseId'];tag='qa-backup140-'+str(rid)+'-'+os.environ.get('GITHUB_RUN_ID','local')
  backup=g.api(REPO+'/releases','POST',{'tag_name':tag,'target_commitish':t['oldSnapshot']['target_commitish'],'name':'Private original140 byte backup '+str(rid),'body':'Rollback byte copies for same-version140 correction. Original release '+str(rid)+'.','draft':True,'prerelease':True,'make_latest':'false'})
  report['backupReleases'].append({'id':backup['id'],'tag':tag,'sourceReleaseId':rid,'assets':[]});save()
  for a in t['oldSnapshot']['assets']:report['backupReleases'][-1]['assets'].append(g.upload(backup['id'],a,folders[rid][0]/a['name']));save()
  assert sorted([asset_pin(a) for a in g.api(REPO+'/releases/'+str(backup['id']))['assets']],key=lambda a:a['name'])==sorted(report['backupReleases'][-1]['assets'],key=lambda a:a['name'])
 for t in plan['targets']:assert snapshot(g.api(REPO+'/releases/'+str(t['releaseId'])))==t['oldSnapshot']
 try:
  report['publicMutationStarted']=True;save()
  for t in plan['targets']:g.api(REPO+'/releases/'+str(t['releaseId']),'PATCH',{'draft':True,'make_latest':'false'})
  for t in plan['targets']:
   rid=t['releaseId'];current=g.api(REPO+'/releases/'+str(rid));assert current['draft'] and current['tag_name']==t['tag'];assert sorted([asset_pin(a) for a in current['assets']],key=lambda a:a['name'])==t['oldSnapshot']['assets']
   for a in t['oldSnapshot']['assets']:g.api(REPO+'/releases/assets/'+str(a['id']),'DELETE')
   for a in t['newAssets']:g.upload(rid,a,folders[rid][1]/a['name'])
   current=g.api(REPO+'/releases/'+str(rid));assert len(current['assets'])==len(t['newAssets'])
   for a in current['assets']:assert any(all(a[k]==x[k] for k in ['name','size','digest']) for x in t['newAssets'])
  for t in plan['targets']:
   value=g.api(REPO+'/releases/'+str(t['releaseId']),'PATCH',{'draft':False,'prerelease':False,'make_latest':'false','body':t['newBody']});assert value['tag_name']==t['tag'] and not value['draft'] and not value['prerelease'];report['published'].append(snapshot(value));save()
  after=g.inventory();backup_ids={b['id'] for b in report['backupReleases']};assert set(after)==set(before)|backup_ids
  assert all(after[rid]==value for rid,value in before.items() if rid not in TARGETS),'Unrelated release metadata changed'
  report['success']=True;report['otherReleasesPreserved']=True;save()
 except Exception as error:
  report['success']=False;report['failureType']=type(error).__name__;report['rollback']=[];save()
  for t in plan['targets']:
   rid=t['releaseId'];old=t['oldSnapshot'];current=g.api(REPO+'/releases/'+str(rid));assert current['tag_name']==old['tag_name']
   g.api(REPO+'/releases/'+str(rid),'PATCH',{'draft':True,'make_latest':'false'})
   expected={a['name']:a for a in old['assets']};known={a['name']:a for a in t['newAssets']}
   for a in current['assets']:
    if a['name'] in expected and all(a[k]==expected[a['name']][k] for k in ['name','size','digest']):continue
    assert a['name'] in known and all(a[k]==known[a['name']][k] for k in ['name','size','digest']),'Unexpected asset; rollback refuses to delete another actor file'
    g.api(REPO+'/releases/assets/'+str(a['id']),'DELETE')
   remaining={a['name'] for a in g.api(REPO+'/releases/'+str(rid))['assets']}
   for a in old['assets']:
    if a['name'] not in remaining:g.upload(rid,a,folders[rid][0]/a['name'])
   restored=g.api(REPO+'/releases/'+str(rid),'PATCH',{**{k:old[k] for k in ['name','body','draft','prerelease','target_commitish']},'make_latest':'false'})
   assert len(restored['assets'])==len(old['assets']) and all(any(all(a[k]==o[k] for k in ['name','size','digest']) for o in old['assets']) for a in restored['assets'])
   report['rollback'].append({'releaseId':rid,'originalBytesRestored':True,'stableRestored':not restored['draft'] and not restored['prerelease']});save()
  report['rollbackComplete']=True;save();raise
 return report

if __name__=='__main__':
 assert os.environ.get('GITHUB_REPOSITORY')==REPO and os.environ.get('GITHUB_REF')=='refs/heads/main'
 asset_id=os.environ['PLAN_ASSET_ID'];pin=os.environ['PLAN_SHA256'];assert re.fullmatch(r'[1-9][0-9]*',asset_id) and re.fullmatch(r'[a-f0-9]{64}',pin)
 g=GitHub();meta=g.api(REPO+'/releases/assets/'+asset_id);require_asset(meta);assert meta['name']=='CyberFi-0.0.140-promotion-plan.json' and meta['digest']=='sha256:'+pin and meta['size']<=256*1024
 root=Path(tempfile.mkdtemp(prefix='cyberfi140-promotion-',dir=os.environ['RUNNER_TEMP']));file=root/'plan.json';g.download(meta,file);plan=validate(json.loads(file.read_text()))
 report=promote(g,plan,root,Path(os.environ['RUNNER_TEMP'])/'promotion-report.json');print(json.dumps({'success':report['success'],'backupReleaseIds':[b['id'] for b in report['backupReleases']],'publishedIds':[p['id'] for p in report['published']]}))
