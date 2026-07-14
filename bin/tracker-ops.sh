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
#   tracker-ops.sh state          <taskId> <Status>                         # set [task] status (generic name)
#   tracker-ops.sh comment        <taskId> [bodyfile]                       # add comment; body from file or stdin
#   tracker-ops.sh update-comment <taskId> <commentId> [bodyfile]           # edit an existing comment (Linear/Jira/GitHub; Markdown refuses)
#   tracker-ops.sh upsert-progress <taskId> [bodyfile]                       # create/update the task's single [progress] artifact
#   tracker-ops.sh upsert-digest   <featureId> [bodyfile]                    # create/update the feature's single [digest] artifact
#   tracker-ops.sh claim          <taskId> <role> [--to <Status>]           # claim: initial→working status + claim comment
#   tracker-ops.sh record-denial  <taskId> --actor <agent> --reason <text> [--denial-id <id>] [bodyfile]
#                                                                            # idempotent [DENIED ACTION] audit comment
#   tracker-ops.sh integrate      <taskId> <hash> [bodyfile]                # terminal move + completion comment citing <hash>
#   tracker-ops.sh export         <featureId> <outfile>                     # read-side: dump the [feature]'s [tasks] as JSON
#   tracker-ops.sh scan           <outfile> --status <Status>...            # board-wide normalized discovery
#   tracker-ops.sh feature-state  <featureId> <Status>                      # set [feature] status (generic name)
#   tracker-ops.sh upsert-deployment <featureId> [bodyfile]                 # one managed [deployment] projection
#
# Adapter comes from PRODUCT_MANAGEMENT_TOOL in config/project-management.config.md
# (override with TRACKER_ADAPTER=<Name>). Credentials come from the environment,
# exactly as the adapter's Access mechanisms section names them. Any failure is an
# andon stop: non-zero exit, no fallback, no fabricated success.
set -euo pipefail

# The script rides on fd 3 so stdin stays free for comment bodies.
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 /dev/fd/3 "$SKILL_DIR" "$@" 3<<'PYEOF'
import hashlib, json, os, re, subprocess, sys, urllib.request, urllib.error
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
FEATURE_STATUSES = BOARD['features']['statuses']

def status_by_name(name):
    for s in TASK_STATUSES:
        if s['name'] == name:
            return s
    die("unknown [task] status '%s' (board: %s)" % (name, ', '.join(x['name'] for x in TASK_STATUSES)))

def feature_status_by_name(name):
    for s in FEATURE_STATUSES:
        if s['name'] == name:
            return s
    die("unknown [feature] status '%s' (board: %s)" % (name, ', '.join(x['name'] for x in FEATURE_STATUSES)))

def tool_value(status):
    v = status.get('tool', {}).get(ADAPTER)
    if v is None:
        die("status '%s' has no '%s' mapping in the board config — andon" % (status['name'], ADAPTER))
    return v

def feature_tool_value(status):
    v = status.get('tool', {}).get(ADAPTER)
    if v is None:
        die("[feature] status '%s' has no '%s' mapping in the board config — andon" % (status['name'], ADAPTER))
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

def feature_generic_of(raw):
    for s in FEATURE_STATUSES:
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

def sanitize_untrusted(text, limit):
    """Bound untrusted agent-supplied text before it becomes tracker evidence."""
    text = ''.join(ch if ch in '\n\t' or ord(ch) >= 32 else ' ' for ch in text).strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + '\n… [truncated for the tracker; the full record stays in protected local logs]'
    return text

def replace_managed_block(text, key, body):
    """Replace one generated block while preserving all user-authored text."""
    start = '<!-- agent-squad:%s:start -->' % key
    end = '<!-- agent-squad:%s:end -->' % key
    block = '%s\n%s\n%s' % (start, body.rstrip(), end)
    pattern = re.compile(re.escape(start) + r'.*?' + re.escape(end), re.S)
    if pattern.search(text or ''):
        return pattern.sub(lambda _m: block, text, count=1)
    text = (text or '').rstrip()
    return (text + '\n\n' if text else '') + block + '\n'

def adf_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return '\n'.join(filter(None, (adf_text(x) for x in value)))
    if isinstance(value, dict):
        own = value.get('text') or ''
        nested = adf_text(value.get('content') or [])
        return '\n'.join(x for x in (own, nested) if x)
    return ''

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

    def current_status(self, task_id):
        d = self.gql('query($id: String!) { issue(id: $id) { state { name } } }', {'id': task_id})
        return generic_of(d['issue']['state']['name']) if d.get('issue') else None

    def integration_comment_exists(self, task_id, commit):
        return self.comment_exists(task_id, 'Integrated: commit %s.' % commit)

    def comment_exists(self, task_id, needle):
        d = self.gql('query($id: String!) { issue(id: $id) { comments { nodes { body } } } }', {'id': task_id})
        return any(needle in (c.get('body') or '')
                   for c in d['issue']['comments']['nodes'])

    def comment(self, task_id, body):
        issue = self.issue(task_id)
        d = self.gql('mutation($id: String!, $body: String!) { commentCreate(input: {issueId: $id, body: $body}) { success comment { id } } }',
                     {'id': issue['id'], 'body': body})
        return d['commentCreate']['comment']['id']

    def update_comment(self, task_id, comment_id, body):
        self.gql('mutation($cid: String!, $body: String!) { commentUpdate(id: $cid, input: {body: $body}) { success } }',
                     {'cid': comment_id, 'body': body})

    def upsert_progress(self, task_id, body):
        issue = self.issue(task_id)
        d = self.gql('query($id: String!) { issue(id: $id) { comments { nodes { id body } } } }',
                     {'id': issue['id']})
        current = next((c for c in d['issue']['comments']['nodes']
                        if (c.get('body') or '').lstrip().startswith('[progress]')), None)
        if current:
            self.update_comment(task_id, current['id'], body)
            return current['id']
        return self.comment(task_id, body)

    def upsert_digest(self, feature_id, body):
        pid = self.project_id(feature_id)
        d = self.gql('query($id: String!) { project(id: $id) { description } }', {'id': pid})
        description = replace_managed_block((d.get('project') or {}).get('description') or '', 'digest', body)
        self.gql('mutation($id: String!, $description: String!) { projectUpdate(id: $id, input: {description: $description}) { success } }',
                 {'id': pid, 'description': description})

    def upsert_deployment(self, feature_id, body):
        pid = self.project_id(feature_id)
        d = self.gql('query($id: String!) { project(id: $id) { description } }', {'id': pid})
        description = replace_managed_block((d.get('project') or {}).get('description') or '', 'deployment', body)
        self.gql('mutation($id: String!, $description: String!) { projectUpdate(id: $id, input: {description: $description}) { success } }',
                 {'id': pid, 'description': description})

    def current_feature_status(self, feature_id):
        d = self.gql('query($id: String!) { project(id: $id) { status { name } } }',
                     {'id': self.project_id(feature_id)})
        raw = ((d.get('project') or {}).get('status') or {}).get('name')
        return feature_generic_of(raw)

    def set_feature_state(self, feature_id, status):
        want = feature_tool_value(status)
        d = self.gql('{ projectStatuses { nodes { id name } } }')
        sid = next((s['id'] for s in d.get('projectStatuses', {}).get('nodes', []) if s.get('name') == want), None)
        if not sid:
            die("Linear workspace has no project status '%s' — andon" % want)
        self.gql('mutation($id: String!, $sid: String!) { projectUpdate(id: $id, input: {statusId: $sid}) { success } }',
                 {'id': self.project_id(feature_id), 'sid': sid})

    def project_id(self, feature_id):
        # The adapter's ID mapping allows a project UUID or a project name.
        if re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', feature_id.lower()):
            return feature_id
        d = self.gql('query($name: String!) { projects(filter: {name: {eq: $name}}) { nodes { id name } } }',
                     {'name': feature_id})
        if not d.get('projects'):
            die("Linear returned no projects data for the name lookup — check LINEAR_API_KEY scope")
        nodes = d['projects']['nodes']
        if len(nodes) != 1:
            die("Linear project named '%s': %d matches — pass the project UUID instead" % (feature_id, len(nodes)))
        return nodes[0]['id']

    def export(self, feature_id):
        d = self.gql('query($id: String!) { project(id: $id) { name issues { nodes { identifier title description updatedAt state { name } assignee { name } labels { nodes { name } } comments { nodes { id body createdAt user { name email } } } inverseRelations { nodes { type issue { identifier } } } } } } }',
                     {'id': self.project_id(feature_id)})
        if not d.get('project'):
            die("no Linear project '%s'" % feature_id)
        tasks = []
        for i in d['project']['issues']['nodes']:
            raw = i['state']['name']
            blocked_by = [r['issue']['identifier']
                          for r in (i.get('inverseRelations') or {}).get('nodes', [])
                          if r.get('type') == 'blocks' and r.get('issue')]
            tasks.append({'taskId': i['identifier'], 'title': i['title'],
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (i.get('assignee') or {}).get('name'),
                          'description': i.get('description'),
                          'comments': [{'id': c.get('id'), 'body': c['body'], 'createdAt': c['createdAt'],
                                        'author': (c.get('user') or {}).get('email') or (c.get('user') or {}).get('name')}
                                       for c in i['comments']['nodes']],
                          'blockedBy': blocked_by,
                          'labels': [x['name'] for x in (i.get('labels') or {}).get('nodes', [])],
                          'updatedAt': i.get('updatedAt'), 'revision': i.get('updatedAt')})
        return tasks

    def scan(self, statuses):
        wanted = {tool_value(status_by_name(name)) for name in statuses}
        team_scope = PM_CONFIG.get('LINEAR_DEFAULT_TEAM')
        items, after = [], None
        query = '''query($after: String) {
          issues(first: 100, after: $after) {
            nodes {
              identifier title description updatedAt
              state { name } assignee { name }
              team { key name }
              project { id name }
              labels { nodes { name } }
              comments { nodes { id body createdAt user { name email } } }
              inverseRelations { nodes { type issue { identifier } } }
            }
            pageInfo { hasNextPage endCursor }
          }
        }'''
        while True:
            d = self.gql(query, {'after': after})['issues']
            for i in d.get('nodes', []):
                raw = (i.get('state') or {}).get('name')
                team = i.get('team') or {}
                if raw not in wanted:
                    continue
                if team_scope and team_scope not in {team.get('key'), team.get('name')}:
                    continue
                project = i.get('project') or {}
                blocked_by = [r['issue']['identifier']
                              for r in (i.get('inverseRelations') or {}).get('nodes', [])
                              if r.get('type') == 'blocks' and r.get('issue')]
                items.append({
                    'featureId': project.get('id'), 'featureTitle': project.get('name'),
                    'taskId': i['identifier'], 'title': i['title'],
                    'status': generic_of(raw), 'statusRaw': raw,
                    'assignee': (i.get('assignee') or {}).get('name'),
                    'description': i.get('description'), 'blockedBy': blocked_by,
                    'comments': [{'id': c.get('id'), 'body': c.get('body'), 'createdAt': c.get('createdAt'),
                                  'author': (c.get('user') or {}).get('email') or (c.get('user') or {}).get('name')}
                                 for c in (i.get('comments') or {}).get('nodes', [])],
                    'labels': [x['name'] for x in (i.get('labels') or {}).get('nodes', [])],
                    'updatedAt': i.get('updatedAt'), 'revision': i.get('updatedAt'),
                })
            page = d.get('pageInfo') or {}
            if not page.get('hasNextPage'):
                break
            after = page.get('endCursor')
            if not after:
                die("Linear pagination said hasNextPage without an endCursor")
        return items

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

    def current_status(self, task_id):
        issue = self.api('/rest/api/3/issue/%s?fields=status' % task_id)
        return generic_of(issue['fields']['status']['name'])

    def integration_comment_exists(self, task_id, commit):
        return self.comment_exists(task_id, 'Integrated: commit %s.' % commit)

    def comment_exists(self, task_id, needle):
        issue = self.api('/rest/api/3/issue/%s?fields=comment' % task_id)
        return any(needle in adf_text(c.get('body'))
                   for c in (issue.get('fields', {}).get('comment') or {}).get('comments', []))

    @staticmethod
    def adf(text):
        return {'type': 'doc', 'version': 1, 'content': [
            {'type': 'paragraph', 'content': [{'type': 'text', 'text': para}]}
            for para in text.split('\n\n')]}

    def comment(self, task_id, body):
        resp = self.api('/rest/api/3/issue/%s/comment' % task_id, {'body': self.adf(body)})
        return resp.get('id')

    def update_comment(self, task_id, comment_id, body):
        self.api('/rest/api/3/issue/%s/comment/%s' % (task_id, comment_id),
                 {'body': self.adf(body)}, method='PUT')

    def upsert_progress(self, task_id, body):
        issue = self.api('/rest/api/3/issue/%s?fields=comment' % task_id)
        comments = (issue.get('fields', {}).get('comment') or {}).get('comments', [])
        current = next((c for c in comments
                        if adf_text(c.get('body')).lstrip().startswith('[progress]')), None)
        if current:
            self.update_comment(task_id, current['id'], body)
            return current['id']
        return self.comment(task_id, body)

    def upsert_digest(self, feature_id, body):
        issue = self.api('/rest/api/3/issue/%s?fields=comment' % feature_id)
        comments = (issue.get('fields', {}).get('comment') or {}).get('comments', [])
        current = next((c for c in comments
                        if adf_text(c.get('body')).lstrip().startswith('[digest]')), None)
        if current:
            self.update_comment(feature_id, current['id'], body)
        else:
            self.comment(feature_id, body)

    def upsert_deployment(self, feature_id, body):
        issue = self.api('/rest/api/3/issue/%s?fields=comment' % feature_id)
        comments = (issue.get('fields', {}).get('comment') or {}).get('comments', [])
        current = next((c for c in comments
                        if adf_text(c.get('body')).lstrip().startswith('[deployment]')), None)
        if current:
            self.update_comment(feature_id, current['id'], body)
        else:
            self.comment(feature_id, body)

    def current_feature_status(self, feature_id):
        issue = self.api('/rest/api/3/issue/%s?fields=status' % feature_id)
        return feature_generic_of(issue['fields']['status']['name'])

    def set_feature_state(self, feature_id, status):
        want = feature_tool_value(status)
        trans = self.api('/rest/api/3/issue/%s/transitions' % feature_id).get('transitions', [])
        tid = next((t['id'] for t in trans if t.get('to', {}).get('name') == want), None)
        if not tid:
            avail = ', '.join(t.get('to', {}).get('name', '?') for t in trans)
            die("no Jira [feature] transition to '%s' (available: %s) — andon" % (want, avail))
        self.api('/rest/api/3/issue/%s/transitions' % feature_id, {'transition': {'id': tid}})

    def export(self, feature_id):
        out = self.api('/rest/api/3/search?jql=%s&fields=summary,description,status,assignee,comment,issuelinks,labels,updated&maxResults=100'
                       % urllib.request.quote('parent=%s' % feature_id))
        tasks = []
        for i in out.get('issues', []):
            f = i['fields']
            raw = f['status']['name']
            blocked_by = [l['inwardIssue']['key'] for l in f.get('issuelinks', [])
                          if l.get('type', {}).get('name') == 'Blocks' and l.get('inwardIssue')]
            tasks.append({'taskId': i['key'], 'title': f['summary'],
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (f.get('assignee') or {}).get('displayName'),
                          'description': adf_text(f.get('description')),
                          'comments': [{'id': c.get('id'), 'body': adf_text(c.get('body')), 'createdAt': c.get('created'),
                                        'author': (c.get('author') or {}).get('accountId') or (c.get('author') or {}).get('displayName')}
                                       for c in (f.get('comment') or {}).get('comments', [])],
                          'blockedBy': blocked_by, 'labels': f.get('labels') or [],
                          'updatedAt': f.get('updated'), 'revision': f.get('updated')})
        return tasks

    def scan(self, statuses):
        raw_statuses = [tool_value(status_by_name(name)) for name in statuses]
        quoted = ','.join('"%s"' % value.replace('"', '\\"') for value in raw_statuses)
        clauses = ['status in (%s)' % quoted]
        if PM_CONFIG.get('JIRA_PROJECT_KEY'):
            clauses.append('project = "%s"' % PM_CONFIG['JIRA_PROJECT_KEY'].replace('"', '\\"'))
        jql = ' AND '.join(clauses)
        items, start = [], 0
        while True:
            path = ('/rest/api/3/search?jql=%s&fields=summary,description,status,assignee,comment,issuelinks,parent,labels,updated'
                    '&startAt=%d&maxResults=100') % (urllib.request.quote(jql), start)
            out = self.api(path)
            rows = out.get('issues', [])
            for i in rows:
                f = i['fields']
                raw = f['status']['name']
                parent = f.get('parent') or {}
                blocked_by = [l['inwardIssue']['key'] for l in f.get('issuelinks', [])
                              if l.get('type', {}).get('name') == 'Blocks' and l.get('inwardIssue')]
                items.append({
                    'featureId': parent.get('key'),
                    'featureTitle': ((parent.get('fields') or {}).get('summary') if isinstance(parent.get('fields'), dict) else None),
                    'taskId': i['key'], 'title': f['summary'],
                    'status': generic_of(raw), 'statusRaw': raw,
                    'assignee': (f.get('assignee') or {}).get('displayName'),
                    'description': adf_text(f.get('description')), 'blockedBy': blocked_by,
                    'comments': [{'id': c.get('id'), 'body': adf_text(c.get('body')), 'createdAt': c.get('created'),
                                  'author': (c.get('author') or {}).get('accountId') or (c.get('author') or {}).get('displayName')}
                                 for c in (f.get('comment') or {}).get('comments', [])],
                    'labels': f.get('labels') or [], 'updatedAt': f.get('updated'), 'revision': f.get('updated'),
                })
            start += len(rows)
            total = int(out.get('total', start))
            if not rows or start >= total:
                break
        return items

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
    def raw_gh(*args, stdin=None):
        cmd = ['gh'] + list(args)
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

    def current_status(self, task_id):
        issue = json.loads(self.gh('issue', 'view', str(task_id), '--json', 'state,labels'))
        label = next((item['name'] for item in issue['labels'] if item['name'].startswith('status:')), None)
        for status in TASK_STATUSES:
            closed, wanted = self.parse_tool_value(tool_value(status))
            if (closed and issue['state'] == 'CLOSED') or (not closed and wanted == label):
                return status['name']
        return None

    def integration_comment_exists(self, task_id, commit):
        return self.comment_exists(task_id, 'Integrated: commit %s.' % commit)

    def comment_exists(self, task_id, needle):
        return any(needle in (comment.get('body') or '')
                   for comment in self.issue_comments(task_id))

    def comment(self, task_id, body):
        out = self.gh('issue', 'comment', str(task_id), '--body-file', '-', stdin=body)
        m = re.search(r'#issuecomment-(\d+)', out)
        return m.group(1) if m else None

    def update_comment(self, task_id, comment_id, body):
        repo = PM_CONFIG.get('GITHUB_REPO')
        if not repo:
            repo = json.loads(self.gh('repo', 'view', '--json', 'nameWithOwner'))['nameWithOwner']
        cmd = ['gh', 'api', '-X', 'PATCH', 'repos/%s/issues/comments/%s' % (repo, comment_id),
               '-f', 'body=%s' % body]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            die("gh CLI not found (see the GitHubIssues adapter's setup)")
        if r.returncode != 0:
            die("gh failed: %s\n%s" % (' '.join(cmd), r.stderr.strip()))

    def repo_name(self):
        if PM_CONFIG.get('GITHUB_REPO'):
            return PM_CONFIG['GITHUB_REPO']
        return json.loads(self.gh('repo', 'view', '--json', 'nameWithOwner'))['nameWithOwner']

    def issue_comments(self, task_id):
        repo = self.repo_name()
        return json.loads(self.raw_gh('api', 'repos/%s/issues/%s/comments?per_page=100' % (repo, task_id)))

    def upsert_progress(self, task_id, body):
        current = next((c for c in self.issue_comments(task_id)
                        if (c.get('body') or '').lstrip().startswith('[progress]')), None)
        if current:
            self.update_comment(task_id, str(current['id']), body)
            return str(current['id'])
        return self.comment(task_id, body)

    def upsert_digest(self, feature_id, body):
        repo = self.repo_name()
        milestones = json.loads(self.raw_gh('api', 'repos/%s/milestones?state=all&per_page=100' % repo))
        current = next((m for m in milestones
                        if str(m.get('number')) == str(feature_id) or m.get('title') == str(feature_id)), None)
        if not current:
            die("no GitHub milestone '%s' — andon" % feature_id)
        description = replace_managed_block(current.get('description') or '', 'digest', body)
        cmd = ['gh', 'api', '-X', 'PATCH', 'repos/%s/milestones/%s' % (repo, current['number']),
               '-f', 'description=%s' % description]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            die("gh failed: %s\n%s" % (' '.join(cmd), r.stderr.strip()))

    def upsert_deployment(self, feature_id, body):
        repo = self.repo_name()
        milestones = json.loads(self.raw_gh('api', 'repos/%s/milestones?state=all&per_page=100' % repo))
        current = next((m for m in milestones
                        if str(m.get('number')) == str(feature_id) or m.get('title') == str(feature_id)), None)
        if not current:
            die("no GitHub milestone '%s' — andon" % feature_id)
        description = replace_managed_block(current.get('description') or '', 'deployment', body)
        cmd = ['gh', 'api', '-X', 'PATCH', 'repos/%s/milestones/%s' % (repo, current['number']),
               '-f', 'description=%s' % description]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            die("gh failed: %s\n%s" % (' '.join(cmd), r.stderr.strip()))

    def milestone(self, feature_id):
        repo = self.repo_name()
        milestones = json.loads(self.raw_gh('api', 'repos/%s/milestones?state=all&per_page=100' % repo))
        current = next((m for m in milestones
                        if str(m.get('number')) == str(feature_id) or m.get('title') == str(feature_id)), None)
        if not current:
            die("no GitHub milestone '%s' — andon" % feature_id)
        return repo, current

    def current_feature_status(self, feature_id):
        _repo, milestone = self.milestone(feature_id)
        if milestone.get('state') == 'closed':
            return next((s['name'] for s in FEATURE_STATUSES if 'closed' in feature_tool_value(s)), None)
        tasks = self.export(feature_id)
        initial = next(s['name'] for s in TASK_STATUSES if s.get('initial'))
        if any(task.get('status') != initial for task in tasks):
            return next((s['name'] for s in FEATURE_STATUSES if s.get('kind') == 'working'), None)
        return next((s['name'] for s in FEATURE_STATUSES if s.get('initial')), None)

    def set_feature_state(self, feature_id, status):
        repo, milestone = self.milestone(feature_id)
        target = 'closed' if 'closed' in feature_tool_value(status) else 'open'
        if milestone.get('state') == target:
            return
        self.raw_gh('api', '-X', 'PATCH', 'repos/%s/milestones/%s' % (repo, milestone['number']),
                    '-f', 'state=%s' % target)

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
                          'comments': [{'id': c.get('id'), 'body': c['body'], 'createdAt': c.get('createdAt'),
                                        'author': ((c.get('author') or {}).get('login') if isinstance(c.get('author'), dict) else c.get('author'))}
                                       for c in comments],
                          'blockedBy': [], 'labels': [l['name'] for l in i['labels']],
                          'updatedAt': i.get('updatedAt'), 'revision': i.get('updatedAt')})
        return tasks

    def scan(self, statuses):
        wanted = set(statuses)
        raw = self.gh('issue', 'list', '--state', 'all', '--limit', '1000',
                      '--json', 'number,title,body,state,labels,assignees,milestone,updatedAt')
        items = []
        for i in json.loads(raw):
            label = next((l['name'] for l in i['labels'] if l['name'].startswith('status:')), None)
            raw_status = 'closed' if i['state'] == 'CLOSED' else 'open + label %s' % (label or '?')
            generic = None
            for status in TASK_STATUSES:
                closed, wanted_label = self.parse_tool_value(tool_value(status))
                if (closed and i['state'] == 'CLOSED') or (not closed and wanted_label and wanted_label == label):
                    generic = status['name']; break
            if generic not in wanted:
                continue
            milestone = i.get('milestone') or {}
            comments = self.issue_comments(i['number'])
            items.append({
                'featureId': milestone.get('number'), 'featureTitle': milestone.get('title'),
                'taskId': i['number'], 'title': i['title'], 'status': generic, 'statusRaw': raw_status,
                'assignee': (i['assignees'][0]['login'] if i['assignees'] else None),
                'description': i.get('body'), 'blockedBy': [],
                'comments': [{'id': c.get('id'), 'body': c.get('body'), 'createdAt': c.get('created_at'),
                              'author': (c.get('user') or {}).get('login')} for c in comments],
                'labels': [l['name'] for l in i['labels']], 'updatedAt': i.get('updatedAt'),
                'revision': i.get('updatedAt'),
            })
        return items

class Markdown:
    def __init__(self):
        configured = PM_CONFIG.get('MARKDOWN_ROOT') or '.workspace/task-manager'
        project_root = os.environ.get('TRACKER_PROJECT_ROOT') or os.getcwd()
        self.root = configured if os.path.isabs(configured) else os.path.join(project_root, configured)

    def contained_path(self, feature_id):
        root = os.path.realpath(self.root)
        path = os.path.realpath(feature_id)
        try:
            inside = os.path.commonpath([root, path]) == root
        except ValueError:
            inside = False
        if not inside:
            die("Markdown feature path escapes MARKDOWN_ROOT: %s" % feature_id)
        return path

    def load(self, feature_id):
        try:
            with open(self.contained_path(feature_id)) as f:
                return f.read()
        except OSError as e:
            die("cannot read feature file '%s': %s — andon" % (feature_id, e))

    def save(self, feature_id, text):
        path = self.contained_path(feature_id)
        if os.path.islink(path):
            die("refusing to write a symlinked Markdown feature: %s" % feature_id)
        with open(path, 'w') as f:
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

    def current_status(self, task_id):
        path, num = self.split_task_id(task_id)
        match = self.section_pattern(num).search(self.load(path))
        if not match:
            die("no task %s in %s — andon" % (num, path))
        return generic_of('[%s]' % match.group(2))

    def integration_comment_exists(self, task_id, commit):
        return self.comment_exists(task_id, 'Integrated: commit %s.' % commit)

    def comment_exists(self, task_id, needle):
        path, num = self.split_task_id(task_id)
        text = self.load(path)
        match = self.section_pattern(num).search(text)
        if not match:
            return False
        rest = text[match.end():]
        nxt = re.search(r'^## ', rest, re.M)
        section = rest[:nxt.start()] if nxt else rest
        return needle in section

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
        if body.startswith('[DENIED ACTION]'):
            # A denied-action audit record keeps its marker literal. Preserve the
            # envelope byte-for-byte (apart from Markdown quote prefixes) instead
            # of folding its first field into the legacy dated first line.
            quoted = '\n'.join('> %s' % line for line in body.split('\n'))
        else:
            quoted = '> %s (%s): %s' % (marker, date.today().isoformat(), lines[0])
            for extra in lines[1:]:
                quoted += '\n> %s' % extra
        rest = text[m.end():]
        nxt = re.search(r'^## ', rest, re.M)
        insert_at = m.end() + (nxt.start() if nxt else len(rest))
        block = text[:insert_at].rstrip('\n') + '\n\n' + quoted + '\n\n'
        self.save(path, block + text[insert_at:].lstrip('\n'))

    def update_comment(self, task_id, comment_id, body):
        die("Markdown adapter is append-only — no stable comment ids; post a new comment with 'supersedes: %s' instead" % comment_id)

    def upsert_progress(self, task_id, body):
        path, num = self.split_task_id(task_id)
        text = self.load(path)
        m = self.section_pattern(num).search(text)
        if not m:
            die("no task %s in %s — andon" % (num, path))
        rest = text[m.end():]
        nxt = re.search(r'^## ', rest, re.M)
        section = rest[:nxt.start()] if nxt else rest
        quoted = '\n'.join('> ' + line for line in body.splitlines())
        updated = replace_managed_block(section, 'progress', quoted)
        self.save(path, text[:m.end()] + updated + (rest[nxt.start():] if nxt else ''))
        return 'managed-progress-%s' % num

    def upsert_digest(self, feature_id, body):
        text = self.load(feature_id)
        first_task = re.search(r'^## ', text, re.M)
        head = text[:first_task.start()] if first_task else text
        tail = text[first_task.start():] if first_task else ''
        quoted = '\n'.join('> ' + line for line in body.splitlines())
        self.save(feature_id, replace_managed_block(head, 'digest', quoted).rstrip() + '\n\n' + tail.lstrip())

    def upsert_deployment(self, feature_id, body):
        text = self.load(feature_id)
        first_task = re.search(r'^## ', text, re.M)
        head = text[:first_task.start()] if first_task else text
        tail = text[first_task.start():] if first_task else ''
        quoted = '\n'.join('> ' + line for line in body.splitlines())
        self.save(feature_id, replace_managed_block(head, 'deployment', quoted).rstrip() + '\n\n' + tail.lstrip())

    def current_feature_status(self, feature_id):
        match = re.search(r'^# .*?\[([^\]]+)\][ \t]*$', self.load(feature_id), re.M)
        if not match:
            die("Markdown feature has no bracketed status: %s" % feature_id)
        return feature_generic_of('[%s]' % match.group(1))

    def set_feature_state(self, feature_id, status):
        text = self.load(feature_id)
        pattern = re.compile(r'^(# .*?)\[([^\]]+)\][ \t]*$', re.M)
        if not pattern.search(text):
            die("Markdown feature has no bracketed status: %s" % feature_id)
        raw = feature_tool_value(status).strip('[]')
        self.save(feature_id, pattern.sub(lambda m: '%s[%s]' % (m.group(1), raw), text, count=1))

    def export(self, feature_id):
        text = self.load(feature_id)
        tasks = []
        for m in re.finditer(r'^## (\d+) (.*?)\[([^\]]+)\][ \t]*$', text, re.M):
            num, title, raw = m.group(1), m.group(2).strip(), '[%s]' % m.group(3)
            rest = text[m.end():]
            nxt = re.search(r'^## ', rest, re.M)
            section = rest[:nxt.start()] if nxt else rest
            am = re.search(r'^\*\*Assignee:\*\* (.*)$', section, re.M)
            bb = re.search(r'^\*\*BlockedBy:\*\* (.*)$', section, re.M)
            blocked_by = ['%s#%s' % (feature_id, n.strip().lstrip('#'))
                          for n in bb.group(1).split(',') if n.strip()] if bb else []
            _blocks, _cur = [], []
            for _l in section.split('\n'):
                _q = re.match(r'^> (.*)$', _l)
                if _q:
                    _cur.append(_q.group(1))
                elif _cur:
                    _b = '\n'.join(_cur).strip()
                    if _b: _blocks.append(_b)
                    _cur = []
            if _cur:
                _b = '\n'.join(_cur).strip()
                if _b: _blocks.append(_b)
            description_lines, managed = [], False
            for _l in section.split('\n'):
                if _l.startswith('<!-- agent-squad:') and _l.endswith(':start -->'):
                    managed = True
                    continue
                if managed:
                    if _l.startswith('<!-- agent-squad:') and _l.endswith(':end -->'):
                        managed = False
                    continue
                if _l.startswith('> ') or re.match(r'^\*\*(Assignee|BlockedBy):\*\*', _l):
                    continue
                description_lines.append(_l)
            description = re.sub(r'\n{3,}', '\n\n', '\n'.join(description_lines)).strip()
            comments = [{'id': ('managed-progress-%s' % num if _b.startswith('[progress]') else None),
                         'body': _b, 'createdAt': None, 'author': None} for _b in _blocks]
            tasks.append({'taskId': '%s#%s' % (feature_id, num), 'title': title,
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (am.group(1).strip() if am and am.group(1).strip() not in ('-', '—') else None),
                          'description': description, 'comments': comments,
                          'blockedBy': blocked_by, 'labels': [],
                          'updatedAt': datetime.fromtimestamp(os.path.getmtime(self.contained_path(feature_id)), timezone.utc).isoformat(),
                          'revision': str(os.stat(self.contained_path(feature_id)).st_mtime_ns)})
        return tasks

    def scan(self, statuses):
        wanted = set(statuses)
        root = self.contained_path(self.root)
        if not os.path.isdir(root):
            die("Markdown root does not exist: %s" % self.root)
        items = []
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(current, name))]
            if 'feature.md' not in files:
                continue
            path = os.path.join(current, 'feature.md')
            text = self.load(path)
            title_match = re.search(r'^# (.*?)\s*\[[^\]]+\][ \t]*$', text, re.M)
            feature_title = title_match.group(1).strip() if title_match else os.path.basename(current)
            for task in self.export(path):
                if task.get('status') not in wanted:
                    continue
                item = dict(task)
                item.update({'featureId': path, 'featureTitle': feature_title})
                items.append(item)
        return items

BACKENDS = {'Linear': Linear, 'Jira': Jira, 'GitHubIssues': GitHubIssues, 'Markdown': Markdown}
if ADAPTER not in BACKENDS:
    die("adapter '%s' has no tracker-ops backend — use the adapter doc's Operations table directly" % ADAPTER)
backend = BACKENDS[ADAPTER]()

# ---- operations ----------------------------------------------------------------
def op_state(args):
    if len(args) != 2:
        die("usage: state <taskId> <Status>")
    target = status_by_name(args[1])
    current_name = backend.current_status(args[0])
    if current_name is None:
        die("cannot reverse-map the current status of %s — andon" % args[0])
    if current_name != target['name']:
        current = status_by_name(current_name)
        if target['name'] not in current.get('transitions', []):
            die("illegal [task] transition [%s] → [%s] — andon" % (current_name, target['name']))
        backend.set_state(args[0], target)
        observed = backend.current_status(args[0])
        if observed != target['name']:
            die("status write did not read back as [%s] (observed: %s) — andon" % (target['name'], observed))
    print("%s → [%s]" % (args[0], args[1]))

def op_feature_state(args):
    if len(args) != 2:
        die("usage: feature-state <featureId> <Status>")
    feature_id, target_name = args
    target = feature_status_by_name(target_name)
    current_name = backend.current_feature_status(feature_id)
    if current_name is None:
        die("cannot reverse-map the current [feature] status of %s — andon" % feature_id)
    if current_name != target_name:
        current = feature_status_by_name(current_name)
        if target_name not in current.get('transitions', []):
            die("illegal [feature] transition [%s] → [%s] — andon" % (current_name, target_name))
        backend.set_feature_state(feature_id, target)
        observed = backend.current_feature_status(feature_id)
        if observed != target_name:
            die("[feature] status write did not read back as [%s] (observed: %s) — andon" % (target_name, observed))
    print("%s → [%s]" % (feature_id, target_name))

def op_comment(args):
    if len(args) not in (1, 2):
        die("usage: comment <taskId> [bodyfile]  (no file / '-' = stdin)")
    body = read_body(args[1] if len(args) == 2 else None)
    if body.count('\n') + 1 > 50:
        print("tracker-ops: warning — comment body exceeds the 50-line budget "
              "(protocol: move detail to <TEAMWORK_ROOT>/<team>/artifacts/ and cite the path)",
              file=sys.stderr)
    cid = backend.comment(args[0], body)
    print("comment added to %s%s" % (args[0], " (id: %s)" % cid if cid else ""))

def op_comment_once(args):
    if len(args) != 3:
        die("usage: comment-once <taskId> <deliveryId> <bodyfile>")
    task_id, delivery_id = args[0], args[1]
    if not re.fullmatch(r'[A-Za-z0-9._:-]+', delivery_id):
        die("invalid delivery id '%s'" % delivery_id)
    body = read_body(args[2])
    token = "delivery-id: %s" % delivery_id
    if token not in body:
        body += "\n\n" + token
    if not backend.comment_exists(task_id, token):
        backend.comment(task_id, body)
    print("comment delivery %s recorded on %s" % (delivery_id, task_id))

def op_update_comment(args):
    if len(args) not in (2, 3):
        die("usage: update-comment <taskId> <commentId> [bodyfile]  (no file / '-' = stdin)")
    if not hasattr(backend, 'update_comment'):
        die("adapter '%s' does not support update-comment" % ADAPTER)
    backend.update_comment(args[0], args[1], read_body(args[2] if len(args) == 3 else None))
    print("comment %s updated on %s" % (args[1], args[0]))

def op_upsert_progress(args):
    if len(args) not in (1, 2):
        die("usage: upsert-progress <taskId> [bodyfile]  (no file / '-' = stdin)")
    body = read_body(args[1] if len(args) == 2 else None)
    if not body.lstrip().startswith('[progress]'):
        die("upsert-progress body must begin with [progress]")
    cid = backend.upsert_progress(args[0], body)
    print("progress updated on %s%s" % (args[0], " (id: %s)" % cid if cid else ""))

def op_upsert_digest(args):
    if len(args) not in (1, 2):
        die("usage: upsert-digest <featureId> [bodyfile]  (no file / '-' = stdin)")
    body = read_body(args[1] if len(args) == 2 else None)
    if not body.lstrip().startswith('[digest]'):
        die("upsert-digest body must begin with [digest]")
    backend.upsert_digest(args[0], body)
    print("digest updated on %s" % args[0])

def op_upsert_deployment(args):
    if len(args) not in (1, 2):
        die("usage: upsert-deployment <featureId> [bodyfile]  (no file / '-' = stdin)")
    body = read_body(args[1] if len(args) == 2 else None)
    if not body.lstrip().startswith('[deployment]'):
        die("upsert-deployment body must begin with [deployment]")
    backend.upsert_deployment(args[0], body)
    print("deployment updated on %s" % args[0])

def op_claim(args):
    to = None
    expected = None
    claim_id = None
    for flag in ('--to', '--expected', '--claim-id'):
        if flag in args:
            i = args.index(flag)
            value = args[i + 1] if i + 1 < len(args) else die("%s needs a value" % flag)
            args = args[:i] + args[i + 2:]
            if flag == '--to': to = value
            elif flag == '--expected': expected = value
            else: claim_id = value
    if len(args) != 2:
        die("usage: claim <taskId> <role> [--to <Status>]")
    task_id, role = args
    init = initial_status()
    expected = expected or init['name']
    if expected != init['name']:
        die("claim expected status must be the board's initial status [%s]" % init['name'])
    if to is None:
        if len(init['transitions']) != 1:
            die("initial status '%s' has %d outbound transitions — pass --to <Status>"
                % (init['name'], len(init['transitions'])))
        to = init['transitions'][0]
    target = status_by_name(to)
    if to not in init['transitions']:
        die("claim must follow the board: '%s' is not in %s.transitions — andon" % (to, init['name']))
    claim_id = claim_id or ('claim-' + hashlib.sha256(('%s\0%s\0%s' % (task_id, role, to)).encode()).hexdigest()[:24])
    if not re.fullmatch(r'[A-Za-z0-9._:-]{8,128}', claim_id):
        die("invalid claim id '%s'" % claim_id)
    token = "claim-id: %s" % claim_id
    current = backend.current_status(task_id)
    if current == to and backend.comment_exists(task_id, token):
        print("%s claim %s already recorded → [%s]" % (task_id, claim_id, to))
        return
    if current != expected:
        die("claim conflict: expected [%s], observed [%s] for %s — no launch" % (expected, current, task_id))
    if not backend.comment_exists(task_id, token):
        backend.comment(task_id, "[claim]\n%s\nrole: %s\ntarget-status: %s\n\n— dispatcher" % (token, role, to))
    if hasattr(backend, 'set_assignee'):
        backend.set_assignee(task_id, role)
    backend.set_state(task_id, target)
    observed = backend.current_status(task_id)
    if observed != to:
        die("claim write did not read back as [%s] (observed: %s) — no launch" % (to, observed))
    print("%s claimed by %s → [%s] (claim-id: %s)" % (task_id, role, to, claim_id))

def op_record_denial(args):
    # A guardrail DENY encountered while an agentic team or dedicated agent acts
    # on a [task] must become ticket-level evidence: what was attempted, by whom,
    # and that the action was prevented. Documentation only — never authorization.
    actor = reason = denial_id = None
    for flag in ('--actor', '--reason', '--denial-id'):
        if flag in args:
            i = args.index(flag)
            value = args[i + 1] if i + 1 < len(args) else die("%s needs a value" % flag)
            args = args[:i] + args[i + 2:]
            if flag == '--actor': actor = value
            elif flag == '--reason': reason = value
            else: denial_id = value
    if len(args) not in (1, 2):
        die("usage: record-denial <taskId> --actor <agent> --reason <text> [--denial-id <id>] [bodyfile]")
    task_id = args[0]
    if not actor or not reason:
        die("record-denial requires --actor and --reason")
    actor = sanitize_untrusted(actor.replace('\n', ' '), 128)
    reason = sanitize_untrusted(reason.replace('\n', '; '), 500)
    if not actor or not reason:
        die("record-denial actor/reason must not be empty after sanitization")
    attempted = sanitize_untrusted(read_body(args[1] if len(args) == 2 else None), 1800)
    if not attempted:
        die("record-denial requires a non-empty attempted-action description")
    denial_id = denial_id or ('denial-' + hashlib.sha256(
        ('%s\0%s\0%s\0%s' % (task_id, actor, reason, attempted)).encode()).hexdigest()[:24])
    if not re.fullmatch(r'[A-Za-z0-9._:-]{8,128}', denial_id):
        die("invalid denial id '%s'" % denial_id)
    token = "denial-id: %s" % denial_id
    if backend.comment_exists(task_id, token):
        print("%s denial %s already recorded" % (task_id, denial_id))
        return
    body = ("[DENIED ACTION]\n%s\nactor: %s\ndecision: DENY\n\n"
            "Attempted action:\n%s\n\n"
            "Denial reason: %s\n\n"
            "This action was blocked by the fail-closed policy gate and was not executed.\n\n"
            "— policy gate" % (token, actor, attempted, reason))
    backend.comment(task_id, body)
    print("%s denial recorded (denial-id: %s)" % (task_id, denial_id))

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
    if backend.current_status(task_id) != term['name']:
        backend.set_state(task_id, term)
    if not backend.integration_comment_exists(task_id, commit):
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

def op_scan(args):
    if not args:
        die("usage: scan <outfile> --status <Status>...")
    outfile, rest = args[0], args[1:]
    statuses = []
    while rest:
        if len(rest) < 2 or rest[0] != '--status':
            die("usage: scan <outfile> --status <Status>...")
        status_by_name(rest[1])
        statuses.append(rest[1])
        rest = rest[2:]
    if not statuses:
        statuses = [s['name'] for s in TASK_STATUSES if s.get('kind') in ('queued', 'blocked')]
    if not statuses:
        die("scan has no statuses (pass --status or configure queued/blocked kinds)")
    items = backend.scan(statuses)
    normalized, orphans = [], []
    for item in items:
        if not isinstance(item, dict) or item.get('taskId') is None:
            die("adapter returned a malformed scan record — andon")
        if item.get('status') not in statuses:
            die("adapter returned an out-of-scope status '%s' for %s" % (item.get('status'), item.get('taskId')))
        value = dict(item)
        value['taskId'] = str(value['taskId'])
        if value.get('featureId') is not None:
            value['featureId'] = str(value['featureId'])
        value['routingHints'] = {'labels': list(value.get('labels') or []), 'teamPreset': None}
        (normalized if value.get('featureId') else orphans).append(value)
    payload = {
        'schemaVersion': 1, 'adapter': ADAPTER,
        'scannedAt': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'statuses': statuses, 'items': normalized, 'orphans': orphans,
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False) + '\n'
    if outfile == '-':
        sys.stdout.write(text)
    else:
        parent = os.path.dirname(os.path.abspath(outfile))
        os.makedirs(parent, exist_ok=True)
        temp = outfile + '.tmp.%d' % os.getpid()
        with open(temp, 'w') as f:
            f.write(text)
        os.replace(temp, outfile)
        print("scanned %d [tasks] (%d orphaned) to %s" % (len(normalized), len(orphans), outfile))

OPS = {'state': op_state, 'comment': op_comment, 'comment-once': op_comment_once, 'update-comment': op_update_comment,
       'upsert-progress': op_upsert_progress, 'upsert-digest': op_upsert_digest,
       'upsert-deployment': op_upsert_deployment, 'feature-state': op_feature_state,
       'claim': op_claim, 'record-denial': op_record_denial, 'integrate': op_integrate,
       'export': op_export, 'scan': op_scan}
if not ARGS or ARGS[0] not in OPS:
    die("usage: tracker-ops.sh {state|feature-state|comment|comment-once|update-comment|upsert-progress|upsert-digest|upsert-deployment|claim|record-denial|integrate|export|scan} ...")
OPS[ARGS[0]](ARGS[1:])
PYEOF
