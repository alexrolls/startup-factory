#!/bin/bash
# Rendered and installed externally by `startup-factory runtime-kit`.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin

engine=@@ENGINE@@
image=@@IMAGE@@
manifest=@@MANIFEST@@
network=@@NETWORK@@
profile=@@PROFILE@@
clone_root=@@CLONE_ROOT@@
outbox_root=@@OUTBOX_ROOT@@
skill_root=@@SKILL_ROOT@@
policy=@@POLICY@@
network_policy=@@NETWORK_POLICY@@
expected_engine_sha256=@@ENGINE_SHA256@@
expected_engine_proof_sha256=@@ENGINE_PROOF_SHA256@@
expected_image_proof_sha256=@@IMAGE_PROOF_SHA256@@
expected_source_assets_sha256=@@SOURCE_ASSETS_SHA256@@

die() { printf 'startup-factory-runner: %s\n' "$*" >&2; exit 1; }
[ "$#" -ge 4 ] && [ "$1" = --workdir ] && [ "$3" = -- ] || die "usage: runner --workdir <broker-issued-clone> -- <argv...>"
workdir="$2"; shift 3
[ "$#" -gt 0 ] || die "missing command"
[ "${STARTUP_FACTORY_AGENT_WORKTREE:-}" = "$workdir" ] || die "workdir does not match the broker-issued runtime identity"

canonical_workdir="$(/usr/bin/python3 - "$0" "$manifest" "$engine" "$policy" "$network_policy" \
  "$image" "$profile" "$clone_root" "$outbox_root" "$workdir" \
  "$skill_root" \
  "$expected_engine_sha256" "$expected_engine_proof_sha256" "$expected_image_proof_sha256" \
  "$expected_source_assets_sha256" "$network" <<'PY'
import hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path

(runner_raw,manifest_raw,engine_raw,policy_raw,network_policy_raw,image,profile,
 clone_root_raw,outbox_root_raw,workdir_raw,skill_root_raw,engine_sha,engine_proof_sha,
 image_proof_sha,source_sha,network)=sys.argv[1:]

def fail(message): raise SystemExit("startup-factory-runner: "+message)
def pairs(rows):
 out={}
 for key,value in rows:
  if key in out: fail("duplicate JSON key")
  out[key]=value
 return out
def read(path_raw,label,maximum=134217728,mode=None,executable=False):
 path=Path(path_raw)
 if not path.is_absolute() or Path(os.path.normpath(str(path))) != path: fail(label+" path is not canonical")
 current=Path(path.anchor)
 for part in path.parts[1:]:
  current/=part
  try: info=current.lstat()
  except OSError: fail(label+" is unavailable")
  if stat.S_ISLNK(info.st_mode): fail(label+" contains a symlink")
 if not getattr(os,"O_NOFOLLOW",0): fail("secure no-follow opens unavailable")
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size>maximum: fail(label+" is unsafe")
  if info.st_uid not in {0,os.geteuid()} or stat.S_IMODE(info.st_mode)&0o022: fail(label+" ownership/mode is unsafe")
  if mode is not None and stat.S_IMODE(info.st_mode)!=mode: fail(label+" mode changed")
  if executable and not info.st_mode&0o111: fail(label+" is not executable")
  content=b""
  while len(content)<=maximum:
   block=os.read(fd,min(65536,maximum+1-len(content)))
   if not block: break
   content+=block
  if len(content)>maximum: fail(label+" exceeds size limit")
  return content
 finally: os.close(fd)
def digest(content): return hashlib.sha256(content).hexdigest()
def strict(content,label):
 try: value=json.loads(content,object_pairs_hook=pairs)
 except (UnicodeError,ValueError): fail(label+" is malformed")
 if not isinstance(value,dict): fail(label+" is not an object")
 return value
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def engine_json(argv,label):
 env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent","XDG_RUNTIME_DIR":"/run/user/%s"%os.geteuid()}
 try: result=subprocess.run([engine_raw,*argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=10)
 except (OSError,subprocess.TimeoutExpired): fail(label+" proof unavailable")
 if result.returncode or result.stderr or len(result.stdout)>262144: fail(label+" proof invalid")
 try: return json.loads(result.stdout,object_pairs_hook=pairs)
 except (UnicodeError,ValueError): fail(label+" proof malformed")
def normalize_proofs():
 info=engine_json(["info","--format","json"],"engine")
 version=info.get("version") if isinstance(info,dict) else None
 host=info.get("host") if isinstance(info,dict) else None
 security=host.get("security") if isinstance(host,dict) else None
 mappings=host.get("idMappings") if isinstance(host,dict) else None
 version_text=version.get("Version") if isinstance(version,dict) else None
 def valid(rows):
  return isinstance(rows,list) and rows and all(isinstance(row,dict) and set(row)=={"container_id","host_id","size"} and all(type(row[k]) is int and row[k]>=0 for k in ("container_id","host_id")) and type(row["size"]) is int and row["size"]>0 for row in rows) and any(row["container_id"]==0 for row in rows)
 if not isinstance(version_text,str) or version_text.split(".",1)[0]!="5" or not isinstance(security,dict) or security.get("rootless") is not True or not isinstance(mappings,dict) or set(mappings)!={"uidmap","gidmap"} or not valid(mappings["uidmap"]) or not valid(mappings["gidmap"]): fail("engine proof no longer matches rootless Podman 5")
 inspected=engine_json(["image","inspect","--format","json",image],"image")
 if not isinstance(inspected,list) or len(inspected)!=1 or not isinstance(inspected[0],dict): fail("image proof cardinality changed")
 repo=inspected[0].get("RepoDigests"); ident=inspected[0].get("Id")
 if not isinstance(repo,list) or image not in repo or not isinstance(ident,str) or not re.fullmatch(r"sha256:[0-9a-f]{64}",ident): fail("image identity changed")
 return {"version":version_text,"rootless":True,"uidmap":mappings["uidmap"],"gidmap":mappings["gidmap"]},{"Id":ident,"RepoDigests":sorted(set(repo))}

runner=read(runner_raw,"runner",2097152,0o700,True)
manifest_content=read(manifest_raw,"manifest",2097152,0o600)
engine_content=read(engine_raw,"engine",134217728,None,True)
policy_content=read(policy_raw,"policy",2097152,0o600)
network_content=read(network_policy_raw,"network policy",2097152,0o600)
value=strict(manifest_content,"manifest")
expected_keys={"schemaVersion","profile","sourceAssetsSha256","engine","image","runner","policy","network","cloneRoot","lifecycleRoot","outboxRoot","skillRoot","readiness","capabilities"}
if set(value)!=expected_keys or value.get("schemaVersion")!=2 or value.get("profile")!=profile or value.get("sourceAssetsSha256")!="sha256:"+source_sha or value.get("cloneRoot")!=clone_root_raw or value.get("outboxRoot")!=outbox_root_raw or value.get("skillRoot")!=skill_root_raw or value.get("readiness")!="configured_unproved" or value.get("capabilities")!={"autonomousDelivery":False,"productionDelivery":False}: fail("manifest identity changed")
for name,path,content in (("runner",runner_raw,runner),("policy",policy_raw,policy_content)):
 if value.get(name)!={"path":path,"sha256":"sha256:"+digest(content)}: fail(name+" manifest binding changed")
if value.get("network")!={"name":network,"path":network_policy_raw,"sha256":"sha256:"+digest(network_content)}: fail("network manifest binding changed")
if value.get("engine")!={"path":engine_raw,"sha256":"sha256:"+engine_sha,"proofSha256":"sha256:"+engine_proof_sha} or digest(engine_content)!=engine_sha: fail("engine manifest binding changed")
if value.get("image")!={"reference":image,"proofSha256":"sha256:"+image_proof_sha,"pull":"never"}: fail("image manifest binding changed")
engine_proof,image_proof=normalize_proofs()
if digest(canonical(engine_proof))!=engine_proof_sha or digest(canonical(image_proof))!=image_proof_sha: fail("live engine/image proof changed")

skill_path=Path(skill_root_raw)
if not skill_path.is_absolute() or Path(os.path.normpath(str(skill_path)))!=skill_path: fail("skill root is not canonical")
current=Path(skill_path.anchor)
for part in skill_path.parts[1:]:
 current/=part; info=current.lstat()
 if stat.S_ISLNK(info.st_mode): fail("skill root contains a symlink")
skill_info=skill_path.lstat()
if not stat.S_ISDIR(skill_info.st_mode) or skill_info.st_uid not in {0,os.geteuid()} or stat.S_IMODE(skill_info.st_mode)&0o022: fail("skill root ownership/mode is unsafe")

clone_root=Path(clone_root_raw).resolve(strict=True); workdir=Path(workdir_raw)
if not workdir.is_absolute() or Path(os.path.normpath(str(workdir)))!=workdir: fail("workdir is not canonical")
current=Path(workdir.anchor)
for part in workdir.parts[1:]:
 current/=part; info=current.lstat()
 if stat.S_ISLNK(info.st_mode): fail("workdir contains a symlink")
resolved=workdir.resolve(strict=True)
try: relative=resolved.relative_to(clone_root)
except ValueError: fail("workdir is outside manifest cloneRoot")
if len(relative.parts)!=2 or not (resolved/".git").is_dir() or (resolved/".git").is_symlink(): fail("workdir is not an exact broker-issued standalone slot")
git_dir=resolved/".git"; forbidden={"commondir","shallow","shallow.lock","info/grafts","objects/info/alternates","objects/info/http-alternates"}
pending=[(git_dir,"",0)]; visited=0
while pending:
 directory,relative_root,depth=pending.pop()
 if depth>64: fail("standalone Git metadata is too deep")
 try: entries=list(os.scandir(directory))
 except OSError: fail("standalone Git metadata is unavailable")
 for entry in entries:
  visited+=1
  if visited>250000: fail("standalone Git metadata is oversized")
  relative_name=(relative_root+"/"+entry.name).lstrip("/"); info=entry.stat(follow_symlinks=False)
  if stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid(): fail("standalone Git metadata identity changed")
  if stat.S_ISDIR(info.st_mode): pending.append((Path(entry.path),relative_name,depth+1)); continue
  if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1: fail("standalone Git metadata contains an unsafe node")
  lowered=relative_name.casefold()
  if lowered in forbidden or lowered.endswith(".promisor"): fail("standalone Git metadata contains hostile indirection")
git_env={"PATH":"/usr/bin:/bin","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_NOSYSTEM":"1","GIT_TERMINAL_PROMPT":"0"}
def git(*argv):
 try: result=subprocess.run(["/usr/bin/git","-c","core.hooksPath=/dev/null","-c","core.fsmonitor=false","-C",str(resolved),*argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=git_env,timeout=15)
 except (OSError,subprocess.TimeoutExpired): fail("standalone Git validation unavailable")
 if result.returncode: fail("standalone Git validation failed")
 return result.stdout.decode("utf-8","strict").strip()
refs=[item for item in git("for-each-ref","--format=%(refname)").splitlines() if item]
if len(refs)!=1 or not refs[0].startswith("refs/heads/") or git("status","--porcelain=v1","-uall"): fail("standalone Git refs or tracked state changed")
config=git("config","--local","--null","--list").casefold()
for unsafe in ("remote.","url.","include.","credential.","filter.","protocol.","core.sshcommand","core.gitproxy"):
 if unsafe in config: fail("standalone Git config contains an unsafe capability")

ingress=os.environ.get("STARTUP_FACTORY_OUTBOX_INGRESS","")
if ingress:
 ingress_path=Path(ingress); root=Path(outbox_root_raw).resolve(strict=True)
 if not ingress_path.is_absolute() or Path(os.path.normpath(str(ingress_path)))!=ingress_path or ingress_path.is_symlink(): fail("outbox ingress path is unsafe")
 resolved_ingress=ingress_path.resolve(strict=True)
 try: ingress_relative=resolved_ingress.relative_to(root)
 except ValueError: fail("outbox ingress is outside manifest outboxRoot")
 info=resolved_ingress.lstat()
 if len(ingress_relative.parts)!=1 or not re.fullmatch(r"cap-[0-9a-f]{32}",ingress_relative.name) or ingress_relative.name!=os.environ.get("STARTUP_FACTORY_OUTBOX_CAPABILITY_ID") or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o077: fail("outbox ingress identity is invalid")
print(resolved)
PY
)" || exit 1
[ "${STARTUP_FACTORY_SKILL_ROOT:-}" = "$skill_root" ] || die "skill root does not match the manifest-bound runtime identity"

uid="$(id -u)"; gid="$(id -g)"
host_env=(-i "PATH=/usr/bin:/bin" "HOME=/nonexistent" "XDG_RUNTIME_DIR=/run/user/$uid")
container_env=(--env HOME=/home/agent --env AWS_EC2_METADATA_DISABLED=true --env STARTUP_FACTORY_SKILL_ROOT="$skill_root")
for name in STARTUP_FACTORY_ROLE STARTUP_FACTORY_TEAM STARTUP_FACTORY_FEATURE_ID \
  STARTUP_FACTORY_PRESET STARTUP_FACTORY_EXECUTION_KIND STARTUP_FACTORY_TASK_ID \
  STARTUP_FACTORY_ATTEMPT STARTUP_FACTORY_INSTANCE STARTUP_FACTORY_AGENT_WORKTREE \
  STARTUP_FACTORY_TASK_WORKTREE STARTUP_FACTORY_OUTBOX_INGRESS \
  STARTUP_FACTORY_SKILL_ROOT \
  STARTUP_FACTORY_OUTBOX_CAPABILITY_ID STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET \
  STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT STARTUP_FACTORY_MODEL_GATEWAY_ENDPOINT \
  STARTUP_FACTORY_MODEL_SESSION_CAPABILITY; do
  [ -z "${!name:-}" ] || container_env+=(--env "$name=${!name}")
done
mounts=(--mount "type=bind,src=$canonical_workdir,dst=$canonical_workdir,rw")
mounts+=(--mount "type=bind,src=$skill_root,dst=$skill_root,ro")
[ -z "${STARTUP_FACTORY_OUTBOX_INGRESS:-}" ] || mounts+=(--mount "type=bind,src=$STARTUP_FACTORY_OUTBOX_INGRESS,dst=$STARTUP_FACTORY_OUTBOX_INGRESS,rw")

exec /usr/bin/env "${host_env[@]}" "$engine" run --rm --pull=never \
  --read-only --userns=keep-id --user "$uid:$gid" --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=256 --memory=2g --cpus=2 \
  --network="$network" --ulimit nofile=1024:1024 \
  --tmpfs /home/agent:rw,nodev,nosuid,noexec,size=256m \
  --tmpfs /tmp:rw,nodev,nosuid,noexec,size=256m \
  --tmpfs /run:rw,nodev,nosuid,noexec,size=64m \
  "${mounts[@]}" --workdir "$canonical_workdir" "${container_env[@]}" "$image" "$@"
