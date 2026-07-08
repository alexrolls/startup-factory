#!/usr/bin/env bash
# tracker-ops.sh — ergonomic CLI for the tracker operations every team run performs
# constantly. Wraps the *scriptable* access mechanisms of the shipped adapters
# (Linear rest, Jira rest, GitHubIssues gh CLI, Markdown files); the adapter doc's
# Operations table remains the spec. Sessions using an MCP mechanism don't need
# this script — the agent has native tools there.
#
# Comment bodies are always read from a file or stdin, never from a shell
# argument — that kills the quoting/escaping failure mode of hand-built API calls.
#
# Usage:
#   tracker-ops.sh state     <taskId> <Status>               # set [task] status (generic name)
#   tracker-ops.sh comment   <taskId> [bodyfile]             # add comment; body from file or stdin
#   tracker-ops.sh claim     <taskId> <role> [--to <Status>] # claim: initial→working status + claim comment
#   tracker-ops.sh integrate <taskId> <hash> [bodyfile]      # terminal move + completion comment citing <hash>
#   tracker-ops.sh export    <featureId> <outfile>           # read-side: dump the [feature]'s [tasks] as JSON
#
# Adapter comes from PRODUCT_MANAGEMENT_TOOL in config/project-management.config.md
# (override with TRACKER_ADAPTER=<Name>). Credentials come from the environment,
# exactly as the adapter's Access mechanisms section names them. Any failure is an
# andon stop: non-zero exit, no fallback, no fabricated success.
set -euo pipefail

# The script rides on fd 3 so stdin stays free for comment bodies.
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 /dev/fd/3 "$SKILL_DIR" "$@" 3<<'PYEOF'
import json, os, re, subprocess, sys, urllib.request, urllib.error
from datetime import date, datetime, timezone

def die(msg):
    print("tracker-ops: %s" % msg, file=sys.stderr)
    sys.exit(1)

SKILL_DIR = sys.argv[1]
ARGS = sys.argv[2:]

# ---- config -----------------------------------------------------------------
def read_config_keys(path):
    keys = {}
    try:
        with open(path) as f:
            for line in f:
                m = re.match(r'^([A-Z_]+)=(.*)$', line.strip())
                if m:
                    v = m.group(2).split('#', 1)[0].strip().strip('"')
                    keys[m.group(1)] = None if v == 'null' else v
    except OSError as e:
        die("cannot read %s: %s" % (path, e))
    return keys

PM_CONFIG = read_config_keys(os.path.join(SKILL_DIR, 'config', 'project-management.config.md'))
ADAPTER = os.environ.get('TRACKER_ADAPTER') or PM_CONFIG.get('PRODUCT_MANAGEMENT_TOOL')
if not ADAPTER:
    die("no adapter: set PRODUCT_MANAGEMENT_TOOL in config/project-management.config.md")

board_path = os.path.join(SKILL_DIR, PM_CONFIG.get('STATUS_CONFIG') or 'config/statuses.config.json')
try:
    with open(board_path) as f:
        BOARD = json.load(f)
except (OSError, ValueError) as e:
    die("cannot load board config %s: %s" % (board_path, e))

TASK_STATUSES = BOARD['tasks']['statuses']

def status_by_name(name):
    for s in TASK_STATUSES:
        if s['name'] == name:
            return s
    die("unknown [task] status '%s' (board: %s)" % (name, ', '.join(x['name'] for x in TASK_STATUSES)))

def tool_value(status):
    v = status.get('tool', {}).get(ADAPTER)
    if v is None:
        die("status '%s' has no '%s' mapping in the board config — andon" % (status['name'], ADAPTER))
    return v

def initial_status():
    return next(s for s in TASK_STATUSES if s.get('initial'))

def terminal_status():
    terms = [s for s in TASK_STATUSES if s.get('terminal')]
    commits = [s for s in terms if s.get('requiresCommit')]
    if len(commits) == 1:
        return commits[0]
    if len(terms) == 1:
        return terms[0]
    die("ambiguous terminal status (%d candidates) — pass an explicit state instead" % len(terms))

def generic_of(raw):  # reverse-map a tool-side status value to the generic name
    for s in TASK_STATUSES:
        if s.get('tool', {}).get(ADAPTER) == raw:
            return s['name']
    return None

def read_body(path):
    if path in (None, '-'):
        body = sys.stdin.read()
    else:
        try:
            with open(path) as f:
                body = f.read()
        except OSError as e:
            die("cannot read body file: %s" % e)
    body = body.rstrip('\n')
    if not body:
        die("empty comment body")
    return body

def env(name):
    v = os.environ.get(name)
    if not v:
        die("missing env var %s (see the %s adapter's access section)" % (name, ADAPTER))
    return v

# ---- adapter backends --------------------------------------------------------
def http_json(url, payload=None, headers=None, method=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method or ('POST' if data else 'GET'))
    req.add_header('Content-Type', 'application/json')
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        die("HTTP %s from %s: %s" % (e.code, url, e.read().decode()[:500]))
    except urllib.error.URLError as e:
        die("request to %s failed: %s" % (url, e.reason))

class Linear:
    def __init__(self):
        self.key = env('LINEAR_API_KEY')

    def gql(self, query, variables=None):
        out = http_json('https://api.linear.app/graphql',
                        {'query': query, 'variables': variables or {}},
                        {'Authorization': self.key})
        if out.get('errors'):
            die("Linear API error: %s" % out['errors'][0].get('message'))
        return out['data']

    def issue(self, task_id):
        d = self.gql('query($id: String!) { issue(id: $id) { id identifier team { id states { nodes { id name } } } } }',
                     {'id': task_id})
        if not d.get('issue'):
            die("no Linear issue '%s'" % task_id)
        return d['issue']

    def set_state(self, task_id, status):
        want = tool_value(status)
        issue = self.issue(task_id)
        states = issue['team']['states']['nodes']
        sid = next((s['id'] for s in states if s['name'] == want), None)
        if not sid:
            die("Linear team has no workflow state '%s' — andon (create it or fix the board mapping)" % want)
        self.gql('mutation($id: String!, $sid: String!) { issueUpdate(id: $id, input: {stateId: $sid}) { success } }',
                 {'id': issue['id'], 'sid': sid})

    def comment(self, task_id, body):
        issue = self.issue(task_id)
        self.gql('mutation($id: String!, $body: String!) { commentCreate(input: {issueId: $id, body: $body}) { success } }',
                 {'id': issue['id'], 'body': body})

    def export(self, feature_id):
        d = self.gql('query($id: String!) { project(id: $id) { name issues { nodes { identifier title description state { name } assignee { name } comments { nodes { body createdAt } } } } } }',
                     {'id': feature_id})
        if not d.get('project'):
            die("no Linear project '%s'" % feature_id)
        tasks = []
        for i in d['project']['issues']['nodes']:
            raw = i['state']['name']
            tasks.append({'taskId': i['identifier'], 'title': i['title'],
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (i.get('assignee') or {}).get('name'),
                          'description': i.get('description'),
                          'comments': [{'body': c['body'], 'createdAt': c['createdAt']}
                                       for c in i['comments']['nodes']]})
        return tasks

class Jira:
    def __init__(self):
        self.base = env('JIRA_BASE_URL').rstrip('/')
        import base64
        tok = base64.b64encode(('%s:%s' % (env('JIRA_EMAIL'), env('JIRA_API_TOKEN'))).encode()).decode()
        self.headers = {'Authorization': 'Basic ' + tok}

    def api(self, path, payload=None, method=None):
        return http_json(self.base + path, payload, self.headers, method)

    def set_state(self, task_id, status):
        want = tool_value(status)
        trans = self.api('/rest/api/3/issue/%s/transitions' % task_id).get('transitions', [])
        tid = next((t['id'] for t in trans if t.get('to', {}).get('name') == want), None)
        if not tid:
            avail = ', '.join(t.get('to', {}).get('name', '?') for t in trans)
            die("no Jira transition to '%s' from the current status (available: %s) — andon" % (want, avail))
        self.api('/rest/api/3/issue/%s/transitions' % task_id, {'transition': {'id': tid}})

    @staticmethod
    def adf(text):
        return {'type': 'doc', 'version': 1, 'content': [
            {'type': 'paragraph', 'content': [{'type': 'text', 'text': para}]}
            for para in text.split('\n\n')]}

    def comment(self, task_id, body):
        self.api('/rest/api/3/issue/%s/comment' % task_id, {'body': self.adf(body)})

    def export(self, feature_id):
        out = self.api('/rest/api/3/search?jql=%s&fields=summary,description,status,assignee,comment&maxResults=100'
                       % urllib.request.quote('parent=%s' % feature_id))
        tasks = []
        for i in out.get('issues', []):
            f = i['fields']
            raw = f['status']['name']
            tasks.append({'taskId': i['key'], 'title': f['summary'],
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (f.get('assignee') or {}).get('displayName'),
                          'description': f.get('description'),
                          'comments': [{'body': c.get('body'), 'createdAt': c.get('created')}
                                       for c in (f.get('comment') or {}).get('comments', [])]})
        return tasks

class GitHubIssues:
    def __init__(self):
        self.repo_args = []
        if PM_CONFIG.get('GITHUB_REPO'):
            self.repo_args = ['-R', PM_CONFIG['GITHUB_REPO']]

    def gh(self, *args, stdin=None):
        cmd = ['gh'] + list(args) + self.repo_args
        try:
            r = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
        except FileNotFoundError:
            die("gh CLI not found (see the GitHubIssues adapter's setup)")
        if r.returncode != 0:
            die("gh failed: %s\n%s" % (' '.join(cmd), r.stderr.strip()))
        return r.stdout

    @staticmethod
    def parse_tool_value(value):  # "open + label status:active" / "closed" -> (closed?, label)
        closed = 'closed' in value and 'open' not in value
        m = re.search(r'(status:[\w-]+)', value)
        return closed, (m.group(1) if m else None)

    def current_status_label(self, task_id):
        labels = json.loads(self.gh('issue', 'view', str(task_id), '--json', 'labels'))['labels']
        return next((l['name'] for l in labels if l['name'].startswith('status:')), None)

    def set_state(self, task_id, status):
        closed, label = self.parse_tool_value(tool_value(status))
        if closed:
            self.gh('issue', 'close', str(task_id))
            return
        if not label:
            die("cannot derive a status:* label from mapping '%s' — andon" % tool_value(status))
        state = json.loads(self.gh('issue', 'view', str(task_id), '--json', 'state'))['state']
        if state == 'CLOSED':
            self.gh('issue', 'reopen', str(task_id))
        old = self.current_status_label(task_id)
        args = ['issue', 'edit', str(task_id), '--add-label', label]
        if old and old != label:
            args += ['--remove-label', old]
        self.gh(*args)

    def comment(self, task_id, body):
        self.gh('issue', 'comment', str(task_id), '--body-file', '-', stdin=body)

    def export(self, feature_id):
        raw = self.gh('issue', 'list', '--milestone', str(feature_id), '--state', 'all',
                      '--json', 'number,title,body,state,labels,assignees')
        tasks = []
        for i in json.loads(raw):
            label = next((l['name'] for l in i['labels'] if l['name'].startswith('status:')), None)
            raw_status = 'closed' if i['state'] == 'CLOSED' else 'open + label %s' % (label or '?')
            generic = None
            for s in TASK_STATUSES:
                closed, lab = self.parse_tool_value(tool_value(s))
                if (closed and i['state'] == 'CLOSED') or (not closed and lab and lab == label):
                    generic = s['name']; break
            comments = json.loads(self.gh('issue', 'view', str(i['number']), '--json', 'comments'))['comments']
            tasks.append({'taskId': i['number'], 'title': i['title'],
                          'status': generic, 'statusRaw': raw_status,
                          'assignee': (i['assignees'][0]['login'] if i['assignees'] else None),
                          'description': i.get('body'),
                          'comments': [{'body': c['body'], 'createdAt': c.get('createdAt')} for c in comments]})
        return tasks

class Markdown:
    def __init__(self):
        self.root = PM_CONFIG.get('MARKDOWN_ROOT') or '.workspace/task-manager'

    def load(self, feature_id):
        try:
            with open(feature_id) as f:
                return f.read()
        except OSError as e:
            die("cannot read feature file '%s': %s — andon" % (feature_id, e))

    def save(self, feature_id, text):
        with open(feature_id, 'w') as f:
            f.write(text)

    @staticmethod
    def split_task_id(task_id):  # "<feature.md path>#<n>" -> (path, n)
        if '#' not in str(task_id):
            die("Markdown taskId must be '<feature-file>#<task-number>' (e.g. .workspace/task-manager/2026-07-06-x/feature.md#2)")
        path, _, num = str(task_id).rpartition('#')
        if not num.isdigit():
            die("bad Markdown task number '%s'" % num)
        return path, num

    def section_pattern(self, num):
        return re.compile(r'^(## %s .*?)\[([^\]]+)\][ \t]*$' % re.escape(num), re.M)

    def set_state(self, task_id, status):
        path, num = self.split_task_id(task_id)
        text = self.load(path)
        pat = self.section_pattern(num)
        if not pat.search(text):
            die("no task %s in %s — andon" % (num, path))
        self.save(path, pat.sub(lambda m: '%s[%s]' % (m.group(1), tool_value(status).strip('[]')), text, count=1))

    def set_assignee(self, task_id, assignee):
        path, num = self.split_task_id(task_id)
        text = self.load(path)
        m = self.section_pattern(num).search(text)
        if not m:
            die("no task %s in %s — andon" % (num, path))
        rest = text[m.end():]
        nxt = re.search(r'^## ', rest, re.M)
        section = rest[:nxt.start()] if nxt else rest
        new_section, n = re.subn(r'^\*\*Assignee:\*\* .*$', '**Assignee:** %s' % assignee, section, count=1, flags=re.M)
        if not n:
            die("task %s in %s has no '**Assignee:**' line — andon" % (num, path))
        self.save(path, text[:m.end()] + new_section + (rest[nxt.start():] if nxt else ''))

    def comment(self, task_id, body):
        path, num = self.split_task_id(task_id)
        text = self.load(path)
        m = self.section_pattern(num).search(text)
        if not m:
            die("no task %s in %s — andon" % (num, path))
        marker_m = re.match(r'^(\[[\w-]+\])', body)
        marker = marker_m.group(1) if marker_m else 'note'
        content = body[len(marker):].lstrip(' :') if marker_m else body
        lines = content.split('\n')
        quoted = '> %s (%s): %s' % (marker, date.today().isoformat(), lines[0])
        for extra in lines[1:]:
            quoted += '\n> %s' % extra
        rest = text[m.end():]
        nxt = re.search(r'^## ', rest, re.M)
        insert_at = m.end() + (nxt.start() if nxt else len(rest))
        block = text[:insert_at].rstrip('\n') + '\n\n' + quoted + '\n\n'
        self.save(path, block + text[insert_at:].lstrip('\n'))

    def export(self, feature_id):
        text = self.load(feature_id)
        tasks = []
        for m in re.finditer(r'^## (\d+) (.*?)\[([^\]]+)\][ \t]*$', text, re.M):
            num, title, raw = m.group(1), m.group(2).strip(), '[%s]' % m.group(3)
            rest = text[m.end():]
            nxt = re.search(r'^## ', rest, re.M)
            section = rest[:nxt.start()] if nxt else rest
            am = re.search(r'^\*\*Assignee:\*\* (.*)$', section, re.M)
            comments = [{'body': c.strip(), 'createdAt': None}
                        for c in re.findall(r'^> (.*)$', section, re.M)]
            tasks.append({'taskId': '%s#%s' % (feature_id, num), 'title': title,
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (am.group(1).strip() if am and am.group(1).strip() != '—' else None),
                          'description': section.strip(), 'comments': comments})
        return tasks

BACKENDS = {'Linear': Linear, 'Jira': Jira, 'GitHubIssues': GitHubIssues, 'Markdown': Markdown}
if ADAPTER not in BACKENDS:
    die("adapter '%s' has no tracker-ops backend — use the adapter doc's Operations table directly" % ADAPTER)
backend = BACKENDS[ADAPTER]()

# ---- operations ----------------------------------------------------------------
def op_state(args):
    if len(args) != 2:
        die("usage: state <taskId> <Status>")
    backend.set_state(args[0], status_by_name(args[1]))
    print("%s → [%s]" % (args[0], args[1]))

def op_comment(args):
    if len(args) not in (1, 2):
        die("usage: comment <taskId> [bodyfile]  (no file / '-' = stdin)")
    backend.comment(args[0], read_body(args[1] if len(args) == 2 else None))
    print("comment added to %s" % args[0])

def op_claim(args):
    to = None
    if '--to' in args:
        i = args.index('--to')
        to = args[i + 1] if i + 1 < len(args) else die("--to needs a status name")
        args = args[:i] + args[i + 2:]
    if len(args) != 2:
        die("usage: claim <taskId> <role> [--to <Status>]")
    task_id, role = args
    init = initial_status()
    if to is None:
        if len(init['transitions']) != 1:
            die("initial status '%s' has %d outbound transitions — pass --to <Status>"
                % (init['name'], len(init['transitions'])))
        to = init['transitions'][0]
    target = status_by_name(to)
    if to not in init['transitions']:
        die("claim must follow the board: '%s' is not in %s.transitions — andon" % (to, init['name']))
    if hasattr(backend, 'set_assignee'):
        backend.set_assignee(task_id, role)
    backend.set_state(task_id, target)
    backend.comment(task_id, "Claimed — moving to [%s].\n\n— %s" % (to, role))
    print("%s claimed by %s → [%s]" % (task_id, role, to))

def op_integrate(args):
    if len(args) not in (2, 3):
        die("usage: integrate <taskId> <commit-hash> [bodyfile]")
    task_id, commit = args[0], args[1]
    if not re.fullmatch(r'[0-9a-f]{7,40}', commit):
        die("'%s' does not look like a commit hash" % commit)
    extra = read_body(args[2]) if len(args) == 3 else None
    term = terminal_status()
    body = "Integrated: commit %s." % commit
    if extra:
        body += "\n\n" + extra
    body += "\n\n— integrator"
    backend.set_state(task_id, term)
    backend.comment(task_id, body)
    print("%s → [%s] (commit %s)" % (task_id, term['name'], commit))

def op_export(args):
    if len(args) != 2:
        die("usage: export <featureId> <outfile>")
    feature_id, outfile = args
    tasks = backend.export(feature_id)
    payload = {'featureId': feature_id, 'adapter': ADAPTER,
               'exportedAt': datetime.now(timezone.utc).isoformat(timespec='seconds'),
               'tasks': tasks}
    with open(outfile, 'w') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print("exported %d [tasks] of %s to %s" % (len(tasks), feature_id, outfile))

OPS = {'state': op_state, 'comment': op_comment, 'claim': op_claim,
       'integrate': op_integrate, 'export': op_export}
if not ARGS or ARGS[0] not in OPS:
    die("usage: tracker-ops.sh {state|comment|claim|integrate|export} ...")
OPS[ARGS[0]](ARGS[1:])
PYEOF
