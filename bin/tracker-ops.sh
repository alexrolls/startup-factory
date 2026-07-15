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
#   tracker-ops.sh feature-reopen <featureId> <Status>                      # PM-supervisor-only terminal→queued reopen
#   tracker-ops.sh task-reopen    <taskId> <Status>                         # integration-broker-only terminal→working rework
#   tracker-ops.sh upsert-deployment <featureId> [bodyfile]                 # one managed [deployment] projection
#
# Adapter comes from PRODUCT_MANAGEMENT_TOOL in config/project-management.config.md
# (override with TRACKER_ADAPTER=<Name>). Credentials come from the environment,
# exactly as the adapter's Access mechanisms section names them. Any failure is an
# andon stop: non-zero exit, no fallback, no fabricated success.
set -euo pipefail

# Preserve caller stdin on fd 4 for comment bodies, then feed the embedded
# program through Python's portable `-` input. Apple's system Python silently
# ignores /dev/fd/N as a script path, so the older fd-3 launcher could report
# success without executing the broker.
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec 4<&0
exec python3 - "$SKILL_DIR" "$@" <<'PYEOF'
import hashlib, importlib.util, json, os, re, stat, subprocess, sys, time, urllib.request, urllib.error, urllib.parse
from datetime import date, datetime, timezone

sys.dont_write_bytecode = True

try:
    sys.stdin = os.fdopen(4)
except OSError:
    # Offline unit tests execute the embedded definitions directly. The real
    # shell entrypoint always preserves caller stdin on fd 4 above.
    pass

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

try:
    OPERATION_TIMEOUT = int(os.environ.get('TRACKER_OPERATION_TIMEOUT_SECONDS', '60'))
except ValueError:
    die("TRACKER_OPERATION_TIMEOUT_SECONDS must be an integer")
if not 1 <= OPERATION_TIMEOUT <= 300:
    die("TRACKER_OPERATION_TIMEOUT_SECONDS must be from 1 to 300")

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

def assert_automated_task_transition(current_name, target_name):
    """Fail closed when an automated operation tries to release a human hold."""
    if current_name == target_name:
        return
    current = status_by_name(current_name)
    if current.get('kind') == 'blocked':
        die("outbound [Blocked] transition [%s] → [%s] is human-only; "
            "move the ticket directly in the project-management tool — andon"
            % (current_name, target_name))

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
    text = text or ''
    matches = list(pattern.finditer(text))
    # A duplicate or half-written managed block is ambiguous: replacing only
    # one copy would preserve conflicting protocol evidence. Refuse every
    # managed projection until an operator repairs the source.
    if text.count(start) != text.count(end) or len(matches) != text.count(start):
        die("managed %s block has unmatched markers — andon" % key)
    if len(matches) > 1:
        die("managed %s block is duplicated — andon" % key)
    if matches:
        return pattern.sub(lambda _m: block, text, count=1)
    text = text.rstrip()
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

GENERIC_TASK_STATUSES = {status['name'] for status in TASK_STATUSES}
NORMALIZED_TASK_FIELDS = {
    'taskId', 'title', 'status', 'statusRaw', 'assignee', 'description',
    'comments', 'blockedBy', 'labels', 'updatedAt', 'revision',
}

def sortable_value(value, context):
    """Return a total-order key for a timestamp/revision or fail closed."""
    if isinstance(value, bool) or value is None:
        die("%s lacks a sortable revision — andon" % context)
    if isinstance(value, (int, float)):
        if not isinstance(value, int) and (value != value or value in (float('inf'), float('-inf'))):
            die("%s has a non-finite revision — andon" % context)
        return (0, value)
    if not isinstance(value, str) or not value.strip():
        die("%s has a malformed revision — andon" % context)
    raw = value.strip()
    markdown = re.fullmatch(r'markdown-offset:([0-9]+)', raw)
    if markdown:
        return (0, int(markdown.group(1)))
    if re.fullmatch(r'[0-9]+', raw):
        return (0, int(raw))
    try:
        stamp = datetime.fromisoformat(raw[:-1] + '+00:00' if raw.endswith('Z') else raw)
    except ValueError:
        die("%s has an unparseable timestamp/revision '%s' — andon" % (context, raw))
    if stamp.tzinfo is None:
        die("%s has a timezone-free timestamp/revision — andon" % context)
    return (1, stamp.astimezone(timezone.utc))

def normalize_string_list(value, field, context, allow_integer=False):
    if not isinstance(value, list):
        die("%s field '%s' must be a list — andon" % (context, field))
    normalized, seen = [], set()
    for raw in value:
        allowed = isinstance(raw, str) or (allow_integer and isinstance(raw, int) and not isinstance(raw, bool))
        if not allowed:
            die("%s field '%s' contains a malformed identity — andon" % (context, field))
        item = str(raw).strip()
        if not item or item in seen:
            die("%s field '%s' contains an empty or duplicate identity — andon" % (context, field))
        seen.add(item)
        normalized.append(item)
    return normalized

def normalize_comments(value, context):
    if not isinstance(value, list):
        die("%s comments must be a list — andon" % context)
    normalized, seen_ids, order = [], set(), []
    for index, raw in enumerate(value):
        cctx = "%s comment %d" % (context, index + 1)
        if not isinstance(raw, dict):
            die("%s is malformed — andon" % cctx)
        required = {'id', 'body', 'createdAt', 'updatedAt', 'revision', 'author'}
        if not required.issubset(raw):
            die("%s omits normalized field(s): %s — andon" %
                (cctx, ', '.join(sorted(required - set(raw)))))
        comment = dict(raw)
        if isinstance(comment['id'], bool) or not isinstance(comment['id'], (str, int)):
            die("%s has a malformed stable id — andon" % cctx)
        comment['id'] = str(comment['id']).strip()
        if not comment['id'] or comment['id'] in seen_ids:
            die("%s has an empty or duplicate stable id — andon" % cctx)
        seen_ids.add(comment['id'])
        if not isinstance(comment['body'], str):
            die("%s body must be a string — andon" % cctx)
        if comment['author'] is not None and not isinstance(comment['author'], str):
            die("%s author must be a string or null — andon" % cctx)
        for field in ('createdAt', 'updatedAt'):
            if comment[field] is not None and not isinstance(comment[field], str):
                die("%s %s must be a timestamp string or null — andon" % (cctx, field))
        if ADAPTER == 'Markdown':
            if comment['createdAt'] is not None or comment['updatedAt'] is not None:
                die("%s Markdown timestamps must be null; use revision — andon" % cctx)
        elif not comment['createdAt'] or not comment['updatedAt']:
            die("%s remote comment omits createdAt/updatedAt — andon" % cctx)
        effective = comment['updatedAt'] or comment['createdAt'] or comment['revision']
        order.append((sortable_value(effective, cctx), comment['id']))
        # revision is mandatory independently of the effective timestamp; it
        # is consumed by gate logic and must never be an incidental null.
        sortable_value(comment['revision'], cctx + ' revision')
        normalized.append(comment)
    if order != sorted(order):
        die("%s comments are not deterministically oldest-first — andon" % context)
    return normalized

def normalize_task_record(raw, context, feature_field=False):
    """Validate and canonicalize the adapter-neutral task wire shape."""
    if not isinstance(raw, dict):
        die("%s is not an object — andon" % context)
    missing = NORMALIZED_TASK_FIELDS - set(raw)
    if missing:
        die("%s omits normalized field(s): %s — andon" %
            (context, ', '.join(sorted(missing))))
    value = dict(raw)
    if isinstance(value['taskId'], bool) or not isinstance(value['taskId'], (str, int)):
        die("%s has a malformed taskId — andon" % context)
    value['taskId'] = str(value['taskId']).strip()
    if not value['taskId']:
        die("%s has an empty taskId — andon" % context)
    if not isinstance(value['title'], str) or not value['title'].strip():
        die("%s has an empty/malformed title — andon" % context)
    if value['status'] not in GENERIC_TASK_STATUSES:
        die("%s has unmapped/unknown generic status '%s' — andon" %
            (context, value.get('status')))
    if not isinstance(value['statusRaw'], str) or not value['statusRaw'].strip():
        die("%s has an empty/malformed raw status — andon" % context)
    for field in ('assignee', 'description'):
        if value[field] is not None and not isinstance(value[field], str):
            die("%s field '%s' must be a string or null — andon" % (context, field))
    if not isinstance(value['updatedAt'], str) or not value['updatedAt'].strip():
        die("%s has an empty/malformed updatedAt — andon" % context)
    sortable_value(value['updatedAt'], context + ' updatedAt')
    sortable_value(value['revision'], context + ' revision')
    value['blockedBy'] = normalize_string_list(
        value['blockedBy'], 'blockedBy', context, allow_integer=True)
    value['labels'] = normalize_string_list(value['labels'], 'labels', context)
    value['comments'] = normalize_comments(value['comments'], context)
    if feature_field:
        missing_feature = {'featureId', 'featureTitle'} - set(value)
        if missing_feature:
            die("%s omits normalized field(s): %s — andon" %
                (context, ', '.join(sorted(missing_feature))))
        if value['featureId'] is not None:
            if isinstance(value['featureId'], bool) or not isinstance(value['featureId'], (str, int)):
                die("%s has a malformed featureId — andon" % context)
            value['featureId'] = str(value['featureId']).strip()
            if not value['featureId']:
                die("%s has an empty featureId — andon" % context)
        if value.get('featureTitle') is not None and not isinstance(value.get('featureTitle'), str):
            die("%s has a malformed featureTitle — andon" % context)
    return value

def ignored_task_labels_from_environment():
    raw = os.environ.get('STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON')
    if raw is None:
        return set()
    try:
        values = json.loads(raw)
    except (TypeError, ValueError) as exc:
        die("STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON is not valid JSON — andon")
    if not isinstance(values, list):
        die("STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON must be a JSON list — andon")
    labels = set()
    for value in values:
        if not isinstance(value, str) or not value or value != value.strip():
            die("STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON contains a malformed label — andon")
        canonical = value.casefold()
        if canonical in labels:
            die("STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON contains a duplicate label — andon")
        labels.add(canonical)
    return labels

def task_has_ignored_label(task, ignored_labels):
    return bool(ignored_labels.intersection(label.casefold() for label in task.get('labels') or []))

# ---- adapter backends --------------------------------------------------------
def http_json(url, payload=None, headers=None, method=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method or ('POST' if data else 'GET'))
    req.add_header('Content-Type', 'application/json')
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=OPERATION_TIMEOUT) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        die("HTTP %s from %s: %s" % (e.code, url, e.read().decode()[:500]))
    except urllib.error.URLError as e:
        die("request to %s failed: %s" % (url, e.reason))
    except TimeoutError:
        die("request to %s exceeded the %ss tracker operation deadline" % (url, OPERATION_TIMEOUT))

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

    @staticmethod
    def mutation_payload(data, key, action):
        payload = data.get(key) if isinstance(data, dict) else None
        if not isinstance(payload, dict) or payload.get('success') is not True:
            die("Linear %s did not return success=true — andon" % action)
        return payload

    def paginate(self, fetch_page, context):
        """Exhaust one Relay connection and fail closed on malformed/stalled cursors."""
        after, nodes, seen = None, [], set()
        while True:
            connection = fetch_page(after)
            if not isinstance(connection, dict) or not isinstance(connection.get('nodes'), list):
                die("Linear %s returned a malformed connection — andon" % context)
            nodes.extend(connection['nodes'])
            page = connection.get('pageInfo')
            if not isinstance(page, dict) or not isinstance(page.get('hasNextPage'), bool):
                die("Linear %s returned malformed pageInfo — andon" % context)
            if not page.get('hasNextPage'):
                return nodes
            after = page.get('endCursor')
            if not after:
                die("Linear %s said hasNextPage without an endCursor — andon" % context)
            if after in seen:
                die("Linear %s repeated pagination cursor '%s' — andon" % (context, after))
            seen.add(after)

    def issue_connection(self, issue_id, connection):
        fields = {
            'comments': 'id body createdAt updatedAt user { name email }',
            'labels': 'name',
            'inverseRelations': 'type issue { identifier }',
        }
        if connection not in fields:
            die("internal error: unsupported Linear issue connection '%s'" % connection)
        query = '''query($id: String!, $after: String) {
          issue(id: $id) {
            %s(first: 100, after: $after) {
              nodes { %s }
              pageInfo { hasNextPage endCursor }
            }
          }
        }''' % (connection, fields[connection])

        def fetch(after):
            issue = self.gql(query, {'id': issue_id, 'after': after}).get('issue')
            if not issue:
                die("no Linear issue '%s'" % issue_id)
            return issue.get(connection)

        return self.paginate(fetch, "issue %s %s" % (issue_id, connection))

    def team_states(self, team_id):
        query = '''query($id: String!, $after: String) {
          team(id: $id) {
            states(first: 100, after: $after) {
              nodes { id name }
              pageInfo { hasNextPage endCursor }
            }
          }
        }'''

        def fetch(after):
            team = self.gql(query, {'id': team_id, 'after': after}).get('team')
            if not team:
                die("no Linear team '%s'" % team_id)
            return team.get('states')

        return self.paginate(fetch, "team %s states" % team_id)

    def resolve_team(self, scope):
        # Resolve an exact key/name before scanning. This makes a typo an andon
        # instead of a deceptively successful empty board scan.
        query = '''query($after: String) {
          teams(first: 100, after: $after) {
            nodes { id key name }
            pageInfo { hasNextPage endCursor }
          }
        }'''
        rows = self.paginate(
            lambda after: self.gql(query, {'after': after}).get('teams'),
            "team lookup")
        matches = {team.get('id'): team for team in rows
                   if scope in (team.get('key'), team.get('name'))}
        matches.pop(None, None)
        if len(matches) != 1:
            die("Linear team scope '%s': %d exact matches — fix LINEAR_DEFAULT_TEAM" % (scope, len(matches)))
        return next(iter(matches.values()))

    @staticmethod
    def normalize_comments(comments):
        rows = [{'id': c.get('id'), 'body': c.get('body'),
                 'createdAt': c.get('createdAt'), 'updatedAt': c.get('updatedAt'),
                 'revision': c.get('updatedAt'),
                 'author': (c.get('user') or {}).get('email') or (c.get('user') or {}).get('name')}
                for c in comments]
        rows.sort(key=lambda c: (c.get('updatedAt') or c.get('createdAt') or '',
                                 str(c.get('id') or '')))
        return rows

    def hydrate_issue(self, issue_id):
        comments = self.issue_connection(issue_id, 'comments')
        labels = self.issue_connection(issue_id, 'labels')
        relations = self.issue_connection(issue_id, 'inverseRelations')
        return {
            'comments': self.normalize_comments(comments),
            'labels': [item['name'] for item in labels],
            'blockedBy': [item['issue']['identifier'] for item in relations
                          if item.get('type') == 'blocks' and item.get('issue')],
        }

    def issue(self, task_id):
        d = self.gql('query($id: String!) { issue(id: $id) { id identifier team { id } } }',
                     {'id': task_id})
        if not d.get('issue'):
            die("no Linear issue '%s'" % task_id)
        issue = d['issue']
        if not issue.get('team') or not issue['team'].get('id'):
            die("Linear issue '%s' has no team — andon" % task_id)
        return issue

    def set_state(self, task_id, status):
        want = tool_value(status)
        issue = self.issue(task_id)
        states = self.team_states(issue['team']['id'])
        sid = next((s['id'] for s in states if s['name'] == want), None)
        if not sid:
            die("Linear team has no workflow state '%s' — andon (create it or fix the board mapping)" % want)
        d = self.gql('mutation($id: String!, $sid: String!) { issueUpdate(id: $id, input: {stateId: $sid}) { success issue { state { name } } } }',
                     {'id': issue['id'], 'sid': sid})
        payload = self.mutation_payload(d, 'issueUpdate', 'issue state update')
        observed = (((payload.get('issue') or {}).get('state') or {}).get('name'))
        if observed != want:
            die("Linear issue state mutation read back '%s', expected '%s' — andon" % (observed, want))

    def current_status(self, task_id):
        d = self.gql('query($id: String!) { issue(id: $id) { state { name } } }', {'id': task_id})
        return generic_of(d['issue']['state']['name']) if d.get('issue') else None

    def current_labels(self, task_id):
        return [item['name'] for item in self.issue_connection(task_id, 'labels')]

    def integration_comment_exists(self, task_id, commit):
        return self.comment_exists(task_id, 'Integrated: commit %s.' % commit)

    def comment_exists(self, task_id, needle):
        return any(needle in (c.get('body') or '')
                   for c in self.issue_connection(task_id, 'comments'))

    def comment(self, task_id, body):
        issue = self.issue(task_id)
        d = self.gql('mutation($id: String!, $body: String!) { commentCreate(input: {issueId: $id, body: $body}) { success comment { id body } } }',
                     {'id': issue['id'], 'body': body})
        payload = self.mutation_payload(d, 'commentCreate', 'comment creation')
        comment = payload.get('comment') or {}
        if not comment.get('id'):
            die("Linear comment creation returned no comment id — andon")
        if comment.get('body') != body:
            die("Linear comment creation did not read back the requested body — andon")
        return comment['id']

    def update_comment(self, task_id, comment_id, body):
        d = self.gql('mutation($cid: String!, $body: String!) { commentUpdate(id: $cid, input: {body: $body}) { success comment { id body } } }',
                     {'cid': comment_id, 'body': body})
        payload = self.mutation_payload(d, 'commentUpdate', 'comment update')
        comment = payload.get('comment') or {}
        if str(comment.get('id')) != str(comment_id) or comment.get('body') != body:
            die("Linear comment update did not read back the requested body — andon")

    def upsert_progress(self, task_id, body):
        issue = self.issue(task_id)
        comments = self.issue_connection(issue['id'], 'comments')
        current = next((c for c in comments
                        if (c.get('body') or '').lstrip().startswith('[progress]')), None)
        if current:
            self.update_comment(task_id, current['id'], body)
            return current['id']
        return self.comment(task_id, body)

    def upsert_digest(self, feature_id, body):
        pid = self.project_id(feature_id)
        d = self.gql('query($id: String!) { project(id: $id) { description } }', {'id': pid})
        description = replace_managed_block((d.get('project') or {}).get('description') or '', 'digest', body)
        d = self.gql('mutation($id: String!, $description: String!) { projectUpdate(id: $id, input: {description: $description}) { success project { description } } }',
                     {'id': pid, 'description': description})
        payload = self.mutation_payload(d, 'projectUpdate', 'project digest update')
        if (payload.get('project') or {}).get('description') != description:
            die("Linear project digest update did not read back the requested description — andon")

    def upsert_deployment(self, feature_id, body):
        pid = self.project_id(feature_id)
        d = self.gql('query($id: String!) { project(id: $id) { description } }', {'id': pid})
        description = replace_managed_block((d.get('project') or {}).get('description') or '', 'deployment', body)
        d = self.gql('mutation($id: String!, $description: String!) { projectUpdate(id: $id, input: {description: $description}) { success project { description } } }',
                     {'id': pid, 'description': description})
        payload = self.mutation_payload(d, 'projectUpdate', 'project deployment update')
        if (payload.get('project') or {}).get('description') != description:
            die("Linear project deployment update did not read back the requested description — andon")

    def current_feature_status(self, feature_id):
        d = self.gql('query($id: String!) { project(id: $id) { status { name } } }',
                     {'id': self.project_id(feature_id)})
        raw = ((d.get('project') or {}).get('status') or {}).get('name')
        return feature_generic_of(raw)

    def set_feature_state(self, feature_id, status):
        want = feature_tool_value(status)
        query = '''query($after: String) {
          projectStatuses(first: 100, after: $after) {
            nodes { id name }
            pageInfo { hasNextPage endCursor }
          }
        }'''
        statuses = self.paginate(
            lambda after: self.gql(query, {'after': after}).get('projectStatuses'),
            "project statuses",
        )
        sid = next((s['id'] for s in statuses if s.get('name') == want), None)
        if not sid:
            die("Linear workspace has no project status '%s' — andon" % want)
        d = self.gql('mutation($id: String!, $sid: String!) { projectUpdate(id: $id, input: {statusId: $sid}) { success project { status { name } } } }',
                     {'id': self.project_id(feature_id), 'sid': sid})
        payload = self.mutation_payload(d, 'projectUpdate', 'project state update')
        observed = (((payload.get('project') or {}).get('status') or {}).get('name'))
        if observed != want:
            die("Linear project state mutation read back '%s', expected '%s' — andon" % (observed, want))

    def project_id(self, feature_id):
        # The adapter's ID mapping allows a project UUID or a project name.
        if re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', feature_id.lower()):
            return feature_id
        d = self.gql('query($name: String!) { projects(first: 2, filter: {name: {eq: $name}}) { nodes { id name } } }',
                     {'name': feature_id})
        if not d.get('projects'):
            die("Linear returned no projects data for the name lookup — check LINEAR_API_KEY scope")
        nodes = d['projects']['nodes']
        if len(nodes) != 1:
            die("Linear project named '%s': %d matches — pass the project UUID instead" % (feature_id, len(nodes)))
        return nodes[0]['id']

    def export(self, feature_id):
        project_id, tasks = self.project_id(feature_id), []
        team_scope = PM_CONFIG.get('LINEAR_DEFAULT_TEAM')
        team = self.resolve_team(team_scope) if team_scope else None
        # Read the entire project before enforcing team scope. Filtering here
        # would silently make a multi-team project look exhaustive.
        query = '''query($id: String!, $after: String) {
          project(id: $id) {
            issues(first: 100, after: $after, includeArchived: true) {
              nodes {
                id identifier title description updatedAt
                state { name } assignee { name }
                team { id key name }
              }
              pageInfo { hasNextPage endCursor }
            }
          }
        }'''
        variables = {'id': project_id}

        def fetch(after):
            page_variables = dict(variables)
            page_variables['after'] = after
            project = self.gql(query, page_variables).get('project')
            if not project:
                die("no Linear project '%s'" % feature_id)
            return project.get('issues')

        for issue in self.paginate(fetch, "project %s issues" % feature_id):
            raw = (issue.get('state') or {}).get('name')
            issue_team = issue.get('team') or {}
            if team and issue_team.get('id') != team['id']:
                die("Linear project export returned issue %s from outside configured team '%s' — andon"
                    % (issue.get('identifier'), team_scope))
            hydrated = self.hydrate_issue(issue['id'])
            tasks.append({'taskId': issue['identifier'], 'title': issue['title'],
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (issue.get('assignee') or {}).get('name'),
                          'description': issue.get('description'),
                          'comments': hydrated['comments'],
                          'blockedBy': hydrated['blockedBy'],
                          'labels': hydrated['labels'],
                          'updatedAt': issue.get('updatedAt'), 'revision': issue.get('updatedAt')})
        return tasks

    def scan(self, statuses):
        wanted = {tool_value(status_by_name(name)) for name in statuses}
        team_scope = PM_CONFIG.get('LINEAR_DEFAULT_TEAM')
        team = self.resolve_team(team_scope) if team_scope else None
        if team:
            available = {state.get('name') for state in self.team_states(team['id'])}
            missing = sorted(wanted - available)
            if missing:
                die("Linear team '%s' has no mapped workflow state(s): %s — fix the board mapping"
                    % (team_scope, ', '.join(missing)))
            query = '''query($after: String, $teamId: ID!, $statuses: [String!]!) {
              issues(first: 100, after: $after,
                     filter: {team: {id: {eq: $teamId}}, state: {name: {in: $statuses}}}) {
                nodes {
                  id identifier title description updatedAt
                  state { name } assignee { name }
                  team { id key name }
                  project { id name }
                }
                pageInfo { hasNextPage endCursor }
              }
            }'''
            variables = {'teamId': team['id'], 'statuses': sorted(wanted)}
        else:
            query = '''query($after: String, $statuses: [String!]!) {
              issues(first: 100, after: $after, filter: {state: {name: {in: $statuses}}}) {
                nodes {
                  id identifier title description updatedAt
                  state { name } assignee { name }
                  team { id key name }
                  project { id name }
                }
                pageInfo { hasNextPage endCursor }
              }
            }'''
            variables = {'statuses': sorted(wanted)}

        def fetch(after):
            page_vars = dict(variables)
            page_vars['after'] = after
            return self.gql(query, page_vars).get('issues')

        items = []
        for issue in self.paginate(fetch, "board issues"):
            raw = (issue.get('state') or {}).get('name')
            issue_team = issue.get('team') or {}
            if raw not in wanted:
                die("Linear server-side status filter returned out-of-scope state '%s' — andon" % raw)
            if team and issue_team.get('id') != team['id']:
                die("Linear server-side team filter returned issue %s from another team — andon"
                    % issue.get('identifier'))
            project = issue.get('project') or {}
            hydrated = self.hydrate_issue(issue['id'])
            items.append({
                'featureId': project.get('id'), 'featureTitle': project.get('name'),
                'taskId': issue['identifier'], 'title': issue['title'],
                'status': generic_of(raw), 'statusRaw': raw,
                'assignee': (issue.get('assignee') or {}).get('name'),
                'description': issue.get('description'), 'blockedBy': hydrated['blockedBy'],
                'comments': hydrated['comments'], 'labels': hydrated['labels'],
                'updatedAt': issue.get('updatedAt'), 'revision': issue.get('updatedAt'),
            })
        return items

class Jira:
    def __init__(self):
        self.base = env('JIRA_BASE_URL').rstrip('/')
        import base64
        tok = base64.b64encode(('%s:%s' % (env('JIRA_EMAIL'), env('JIRA_API_TOKEN'))).encode()).decode()
        self.headers = {'Authorization': 'Basic ' + tok}

    def api(self, path, payload=None, method=None):
        return http_json(self.base + path, payload, self.headers, method)

    @staticmethod
    def config_scope_value(name):
        value = PM_CONFIG.get(name)
        if (not isinstance(value, str) or not value or value != value.strip() or
                len(value) > 255 or any(ord(char) < 32 for char in value)):
            die("Jira automation requires a non-empty, canonical %s — andon" % name)
        return value

    @staticmethod
    def jql_string(value):
        """Quote an operator- or tracker-provided identity as one JQL string."""
        return '"%s"' % value.replace('\\', '\\\\').replace('"', '\\"')

    def resolve_scope(self):
        """Resolve the configured project exactly before any exhaustive read."""
        project_key = self.config_scope_value('JIRA_PROJECT_KEY')
        task_issue_type = self.config_scope_value('JIRA_TASK_ISSUE_TYPE')
        if task_issue_type.casefold() == 'epic':
            die("JIRA_TASK_ISSUE_TYPE must name a child task type, never Epic — andon")
        project = self.api('/rest/api/3/project/%s' %
                           urllib.parse.quote(project_key, safe=''))
        if not isinstance(project, dict):
            die("Jira project lookup returned a malformed project — andon")
        observed = project.get('key')
        if observed != project_key:
            die("Jira project lookup resolved key '%s', expected exact key '%s' — andon"
                % (observed, project_key))
        return project_key, task_issue_type

    @staticmethod
    def scoped_issue_fields(issue, project_key, task_issue_type, context):
        if not isinstance(issue, dict) or not isinstance(issue.get('fields'), dict):
            die("%s returned a malformed Jira issue — andon" % context)
        issue_key = issue.get('key')
        if not isinstance(issue_key, str) or not issue_key:
            die("%s returned a Jira issue without a key — andon" % context)
        fields = issue['fields']
        observed_project = ((fields.get('project') or {}).get('key')
                            if isinstance(fields.get('project'), dict) else None)
        if observed_project != project_key:
            die("%s returned issue %s from project '%s', expected '%s' — andon"
                % (context, issue_key, observed_project, project_key))
        observed_type = ((fields.get('issuetype') or {}).get('name')
                         if isinstance(fields.get('issuetype'), dict) else None)
        if observed_type != task_issue_type:
            die("%s returned issue %s with type '%s', expected child task type '%s' — andon"
                % (context, issue_key, observed_type, task_issue_type))
        return fields

    def comments(self, task_id):
        rows, start, page_size = [], 0, 100
        while True:
            path = ('/rest/api/3/issue/%s/comment?startAt=%d&maxResults=%d'
                    % (urllib.request.quote(str(task_id), safe=''), start, page_size))
            out = self.api(path)
            page = out.get('comments')
            if not isinstance(page, list):
                die("Jira comments for %s returned a malformed page — andon" % task_id)
            rows.extend(page)
            start += len(page)
            total = out.get('total')
            if total is not None:
                try:
                    total = int(total)
                except (TypeError, ValueError):
                    die("Jira comments for %s returned an invalid total — andon" % task_id)
                if start >= total:
                    break
                if not page:
                    die("Jira comments for %s ended before total=%d — andon" % (task_id, total))
            elif out.get('isLast') is True or len(page) < page_size:
                break
            elif not page:
                die("Jira comments for %s stalled during pagination — andon" % task_id)
        rows.sort(key=lambda c: (c.get('updated') or c.get('created') or '',
                                 str(c.get('id') or '')))
        return rows

    def search_all(self, jql, fields):
        # Jira's enhanced search is a scrolling/token API. The legacy
        # /rest/api/3/search startAt endpoint is being removed and can produce
        # inconsistent pages while issues move during a scan.
        rows, token, seen_tokens, page_size = [], None, set(), 100
        field_names = [field.strip() for field in fields.split(',') if field.strip()]
        if not field_names:
            die("Jira enhanced search requires at least one field — andon")
        while True:
            payload = {'jql': jql, 'fields': field_names, 'maxResults': page_size}
            if token is not None:
                payload['nextPageToken'] = token
            out = self.api('/rest/api/3/search/jql', payload, method='POST')
            page = out.get('issues')
            if not isinstance(page, list):
                die("Jira search returned a malformed issue page — andon")
            if any(not isinstance(issue, dict) for issue in page):
                die("Jira search returned a malformed issue record — andon")
            rows.extend(page)
            if not isinstance(out.get('isLast'), bool):
                die("Jira enhanced search omitted boolean isLast — andon")
            if out['isLast']:
                return rows
            next_token = out.get('nextPageToken')
            if not isinstance(next_token, str) or not next_token:
                die("Jira enhanced search is not last but omitted nextPageToken — andon")
            if next_token in seen_tokens:
                die("Jira enhanced search repeated nextPageToken — andon")
            if not page:
                die("Jira enhanced search stalled on an empty non-final page — andon")
            seen_tokens.add(next_token)
            token = next_token

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

    def current_labels(self, task_id):
        issue = self.api('/rest/api/3/issue/%s?fields=labels' % task_id)
        labels = issue.get('fields', {}).get('labels') or []
        if not isinstance(labels, list) or any(not isinstance(item, str) for item in labels):
            die("Jira returned malformed task labels — andon")
        return labels

    def integration_comment_exists(self, task_id, commit):
        return self.comment_exists(task_id, 'Integrated: commit %s.' % commit)

    def comment_exists(self, task_id, needle):
        return any(needle in adf_text(c.get('body'))
                   for c in self.comments(task_id))

    @staticmethod
    def adf(text):
        return {'type': 'doc', 'version': 1, 'content': [
            {'type': 'paragraph', 'content': [{'type': 'text', 'text': para}]}
            for para in text.split('\n\n')]}

    def comment(self, task_id, body):
        resp = self.api('/rest/api/3/issue/%s/comment' % task_id, {'body': self.adf(body)})
        if not resp.get('id'):
            die("Jira comment creation returned no comment id — andon")
        return resp['id']

    def update_comment(self, task_id, comment_id, body):
        resp = self.api('/rest/api/3/issue/%s/comment/%s' % (task_id, comment_id),
                        {'body': self.adf(body)}, method='PUT')
        if str(resp.get('id')) != str(comment_id):
            die("Jira comment update did not read back comment %s — andon" % comment_id)

    def upsert_progress(self, task_id, body):
        comments = self.comments(task_id)
        current = next((c for c in comments
                        if adf_text(c.get('body')).lstrip().startswith('[progress]')), None)
        if current:
            self.update_comment(task_id, current['id'], body)
            return current['id']
        return self.comment(task_id, body)

    def upsert_digest(self, feature_id, body):
        comments = self.comments(feature_id)
        current = next((c for c in comments
                        if adf_text(c.get('body')).lstrip().startswith('[digest]')), None)
        if current:
            self.update_comment(feature_id, current['id'], body)
        else:
            self.comment(feature_id, body)

    def upsert_deployment(self, feature_id, body):
        comments = self.comments(feature_id)
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
        project_key, task_issue_type = self.resolve_scope()
        jql = ' AND '.join([
            'project = %s' % self.jql_string(project_key),
            'issuetype = %s' % self.jql_string(task_issue_type),
            'parent = %s' % self.jql_string(str(feature_id)),
        ])
        tasks = []
        issues = self.search_all(
            jql,
            'summary,description,status,assignee,issuelinks,labels,updated,project,issuetype')
        for i in issues:
            f = self.scoped_issue_fields(
                i, project_key, task_issue_type, "Jira feature export")
            raw = f['status']['name']
            blocked_by = [l['inwardIssue']['key'] for l in f.get('issuelinks', [])
                          if l.get('type', {}).get('name') == 'Blocks' and l.get('inwardIssue')]
            comments = self.comments(i['key'])
            tasks.append({'taskId': i['key'], 'title': f['summary'],
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (f.get('assignee') or {}).get('displayName'),
                          'description': adf_text(f.get('description')),
                          'comments': [{'id': c.get('id'), 'body': adf_text(c.get('body')),
                                        'createdAt': c.get('created'), 'updatedAt': c.get('updated'),
                                        'revision': c.get('updated'),
                                        'author': (c.get('author') or {}).get('accountId') or (c.get('author') or {}).get('displayName')}
                                       for c in comments],
                          'blockedBy': blocked_by, 'labels': f.get('labels') or [],
                          'updatedAt': f.get('updated'), 'revision': f.get('updated')})
        return tasks

    def scan(self, statuses):
        project_key, task_issue_type = self.resolve_scope()
        raw_statuses = [tool_value(status_by_name(name)) for name in statuses]
        quoted = ','.join(self.jql_string(value) for value in raw_statuses)
        clauses = [
            'project = %s' % self.jql_string(project_key),
            'issuetype = %s' % self.jql_string(task_issue_type),
            'status in (%s)' % quoted,
        ]
        jql = ' AND '.join(clauses)
        items = []
        rows = self.search_all(jql,
                               'summary,description,status,assignee,issuelinks,parent,labels,updated,project,issuetype')
        for i in rows:
            f = self.scoped_issue_fields(
                i, project_key, task_issue_type, "Jira board scan")
            raw = f['status']['name']
            if raw not in raw_statuses:
                die("Jira server-side status filter returned issue %s in state '%s' — andon"
                    % (i.get('key'), raw))
            parent = f.get('parent') or {}
            blocked_by = [l['inwardIssue']['key'] for l in f.get('issuelinks', [])
                          if l.get('type', {}).get('name') == 'Blocks' and l.get('inwardIssue')]
            comments = self.comments(i['key'])
            items.append({
                'featureId': parent.get('key'),
                'featureTitle': ((parent.get('fields') or {}).get('summary') if isinstance(parent.get('fields'), dict) else None),
                'taskId': i['key'], 'title': f['summary'],
                'status': generic_of(raw), 'statusRaw': raw,
                'assignee': (f.get('assignee') or {}).get('displayName'),
                'description': adf_text(f.get('description')), 'blockedBy': blocked_by,
                'comments': [{'id': c.get('id'), 'body': adf_text(c.get('body')),
                              'createdAt': c.get('created'), 'updatedAt': c.get('updated'),
                              'revision': c.get('updated'),
                              'author': (c.get('author') or {}).get('accountId') or (c.get('author') or {}).get('displayName')}
                             for c in comments],
                'labels': f.get('labels') or [], 'updatedAt': f.get('updated'), 'revision': f.get('updated'),
            })
        return items

class GitHubIssues:
    def __init__(self):
        self.repo_args = []
        if PM_CONFIG.get('GITHUB_REPO'):
            self.repo_args = ['-R', PM_CONFIG['GITHUB_REPO']]

    def gh(self, *args, stdin=None):
        cmd = ['gh'] + list(args) + self.repo_args
        try:
            r = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                               timeout=OPERATION_TIMEOUT)
        except FileNotFoundError:
            die("gh CLI not found (see the GitHubIssues adapter's setup)")
        except subprocess.TimeoutExpired:
            die("gh exceeded the %ss tracker operation deadline" % OPERATION_TIMEOUT)
        if r.returncode != 0:
            die("gh failed: %s\n%s" % (' '.join(cmd), r.stderr.strip()))
        return r.stdout

    @staticmethod
    def raw_gh(*args, stdin=None):
        cmd = ['gh'] + list(args)
        try:
            r = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                               timeout=OPERATION_TIMEOUT)
        except FileNotFoundError:
            die("gh CLI not found (see the GitHubIssues adapter's setup)")
        except subprocess.TimeoutExpired:
            die("gh exceeded the %ss tracker operation deadline" % OPERATION_TIMEOUT)
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

    def current_labels(self, task_id):
        issue = json.loads(self.gh('issue', 'view', str(task_id), '--json', 'labels'))
        labels = issue.get('labels') or []
        if not isinstance(labels, list) or any(
            not isinstance(item, dict) or not isinstance(item.get('name'), str)
            for item in labels
        ):
            die("GitHub returned malformed task labels — andon")
        return [item['name'] for item in labels]

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
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=OPERATION_TIMEOUT)
        except FileNotFoundError:
            die("gh CLI not found (see the GitHubIssues adapter's setup)")
        except subprocess.TimeoutExpired:
            die("gh exceeded the %ss tracker operation deadline" % OPERATION_TIMEOUT)
        if r.returncode != 0:
            die("gh failed: %s\n%s" % (' '.join(cmd), r.stderr.strip()))

    def repo_name(self):
        if PM_CONFIG.get('GITHUB_REPO'):
            return PM_CONFIG['GITHUB_REPO']
        return json.loads(self.gh('repo', 'view', '--json', 'nameWithOwner'))['nameWithOwner']

    @staticmethod
    def endpoint(path, **params):
        return path + (('?' + urllib.parse.urlencode(params)) if params else '')

    def paginated_list(self, endpoint, resource):
        """Read every REST page, refusing partial or structurally ambiguous data."""
        raw = self.raw_gh('api', '--paginate', '--slurp', endpoint)
        try:
            pages = json.loads(raw)
        except (TypeError, ValueError) as e:
            die("GitHub %s pagination returned invalid JSON: %s — andon" % (resource, e))
        if not isinstance(pages, list) or not pages:
            die("GitHub %s pagination returned a malformed outer result — andon" % resource)
        rows = []
        for page_number, page in enumerate(pages, 1):
            if not isinstance(page, list):
                die("GitHub %s pagination returned malformed page %d — andon" %
                    (resource, page_number))
            if any(not isinstance(row, dict) for row in page):
                die("GitHub %s pagination returned a malformed item on page %d — andon" %
                    (resource, page_number))
            rows.extend(page)
        return rows

    def milestones(self):
        repo = self.repo_name()
        rows = self.paginated_list(
            self.endpoint('repos/%s/milestones' % repo, state='all', per_page=100),
            'milestones')
        if any('number' not in row or 'title' not in row or 'state' not in row for row in rows):
            die("GitHub milestones response omitted required fields — andon")
        return rows

    def repository_issues(self, milestone_number=None):
        repo = self.repo_name()
        params = {'state': 'all', 'per_page': 100}
        if milestone_number is not None:
            params['milestone'] = str(milestone_number)
        rows = self.paginated_list(
            self.endpoint('repos/%s/issues' % repo, **params), 'issues')
        # GitHub's repository issues REST endpoint deliberately includes pull
        # requests. A pull_request key is the documented discriminator.
        issues = [row for row in rows if 'pull_request' not in row]
        required = ('number', 'title', 'state', 'labels', 'assignees', 'updated_at')
        if any(any(field not in issue for field in required) for issue in issues):
            die("GitHub issues response omitted required fields — andon")
        if any(not isinstance(issue['labels'], list) or
               not isinstance(issue['assignees'], list) or
               (issue.get('milestone') is not None and
                not isinstance(issue.get('milestone'), dict))
               for issue in issues):
            die("GitHub issues response contained malformed nested fields — andon")
        return issues

    @staticmethod
    def issue_label_names(issue):
        names = []
        for label in issue['labels']:
            if isinstance(label, str):
                name = label
            elif isinstance(label, dict):
                name = label.get('name')
            else:
                name = None
            if not isinstance(name, str) or not name:
                die("GitHub issue %s has a malformed label — andon" % issue['number'])
            names.append(name)
        return names

    @staticmethod
    def primary_assignee(issue):
        if not issue['assignees']:
            return None
        assignee = issue['assignees'][0]
        if not isinstance(assignee, dict) or not isinstance(assignee.get('login'), str):
            die("GitHub issue %s has a malformed assignee — andon" % issue['number'])
        return assignee['login']

    def generic_issue_status(self, issue, labels):
        state = str(issue['state']).upper()
        if state not in ('OPEN', 'CLOSED'):
            die("GitHub issue %s has unknown state '%s' — andon" %
                (issue['number'], issue['state']))
        status_labels = [name for name in labels if name.startswith('status:')]
        if state == 'OPEN' and len(status_labels) != 1:
            die("GitHub open issue %s must have exactly one status:* label — andon" %
                issue['number'])
        label = status_labels[0] if status_labels else None
        matches = []
        for status in TASK_STATUSES:
            closed, wanted = self.parse_tool_value(tool_value(status))
            if (closed and state == 'CLOSED') or (not closed and wanted and wanted == label):
                matches.append(status['name'])
        if len(matches) != 1:
            raw = 'closed' if state == 'CLOSED' else 'open + label %s' % (label or '?')
            die("GitHub issue %s status '%s' has %d generic mappings — andon" %
                (issue['number'], raw, len(matches)))
        raw = 'closed' if state == 'CLOSED' else 'open + label %s' % label
        return matches[0], raw

    def issue_comments(self, task_id):
        repo = self.repo_name()
        comments = self.paginated_list(
            self.endpoint('repos/%s/issues/%s/comments' % (repo, task_id), per_page=100),
            'comments for issue %s' % task_id)
        if any('id' not in comment or 'body' not in comment or
               'created_at' not in comment or 'updated_at' not in comment
               for comment in comments):
            die("GitHub comments for issue %s omitted required fields — andon" % task_id)
        if any(not isinstance(comment['created_at'], str) or
               not isinstance(comment['updated_at'], str) or
               (comment.get('user') is not None and not isinstance(comment.get('user'), dict))
               for comment in comments):
            die("GitHub comments for issue %s contained malformed fields — andon" % task_id)
        # REST pages are an implementation detail. Return one deterministic,
        # oldest-first modification timeline even if pages arrive out of order.
        return sorted(comments, key=lambda comment:
                      (comment['updated_at'], str(comment['id'])))

    def issue_blocked_by(self, task_id):
        """Exhaust GitHub's first-class issue-dependency connection."""
        repo = self.repo_name()
        endpoint = self.endpoint(
            'repos/%s/issues/%s/dependencies/blocked_by' % (repo, task_id),
            per_page=100)
        try:
            dependencies = self.paginated_list(
                endpoint, 'blocked-by dependencies for issue %s' % task_id)
        except SystemExit:
            # Older GitHub Enterprise versions, disabled feature surfaces,
            # missing token scopes, and partial pagination are all unsafe: an
            # empty fallback would incorrectly auto-unblock work.
            die("GitHub blocked_by dependency endpoint for issue %s is unavailable, "
                "unsupported, unauthorized, or incomplete — andon" % task_id)
        blocked_by, seen = [], set()
        for dependency in dependencies:
            number = dependency.get('number')
            if isinstance(number, bool) or not isinstance(number, (str, int)):
                die("GitHub blocked_by dependency for issue %s omitted a stable issue number — andon"
                    % task_id)
            number = str(number).strip()
            if not number or number in seen:
                die("GitHub blocked_by dependency for issue %s has an empty/duplicate issue number — andon"
                    % task_id)
            seen.add(number)
            blocked_by.append(number)
        return blocked_by

    def upsert_progress(self, task_id, body):
        current = next((c for c in self.issue_comments(task_id)
                        if (c.get('body') or '').lstrip().startswith('[progress]')), None)
        if current:
            self.update_comment(task_id, str(current['id']), body)
            return str(current['id'])
        return self.comment(task_id, body)

    def upsert_digest(self, feature_id, body):
        repo, current = self.milestone(feature_id)
        description = replace_managed_block(current.get('description') or '', 'digest', body)
        cmd = ['gh', 'api', '-X', 'PATCH', 'repos/%s/milestones/%s' % (repo, current['number']),
               '-f', 'description=%s' % description]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=OPERATION_TIMEOUT)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            die("gh milestone update could not complete: %s" % exc)
        if r.returncode != 0:
            die("gh failed: %s\n%s" % (' '.join(cmd), r.stderr.strip()))

    def upsert_deployment(self, feature_id, body):
        repo, current = self.milestone(feature_id)
        description = replace_managed_block(current.get('description') or '', 'deployment', body)
        cmd = ['gh', 'api', '-X', 'PATCH', 'repos/%s/milestones/%s' % (repo, current['number']),
               '-f', 'description=%s' % description]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=OPERATION_TIMEOUT)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            die("gh milestone update could not complete: %s" % exc)
        if r.returncode != 0:
            die("gh failed: %s\n%s" % (' '.join(cmd), r.stderr.strip()))

    def milestone(self, feature_id):
        repo = self.repo_name()
        current = next((m for m in self.milestones()
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
        _repo, milestone = self.milestone(feature_id)
        tasks = []
        for i in self.repository_issues(milestone['number']):
            labels = self.issue_label_names(i)
            generic, raw_status = self.generic_issue_status(i, labels)
            comments = self.issue_comments(i['number'])
            blocked_by = self.issue_blocked_by(i['number'])
            tasks.append({'taskId': i['number'], 'title': i['title'],
                          'status': generic, 'statusRaw': raw_status,
                          'assignee': self.primary_assignee(i),
                          'description': i.get('body'),
                          'comments': [{'id': c.get('id'), 'body': c['body'],
                                        'createdAt': c.get('created_at'), 'updatedAt': c.get('updated_at'),
                                        'revision': c.get('updated_at'),
                                        'author': (c.get('user') or {}).get('login')}
                                       for c in comments],
                          'blockedBy': blocked_by, 'labels': labels,
                          'updatedAt': i.get('updated_at'), 'revision': i.get('updated_at')})
        return tasks

    def scan(self, statuses):
        wanted = set(statuses)
        items = []
        for i in self.repository_issues():
            labels = self.issue_label_names(i)
            generic, raw_status = self.generic_issue_status(i, labels)
            if generic not in wanted:
                continue
            milestone = i.get('milestone') or {}
            comments = self.issue_comments(i['number'])
            blocked_by = self.issue_blocked_by(i['number'])
            items.append({
                'featureId': milestone.get('number'), 'featureTitle': milestone.get('title'),
                'taskId': i['number'], 'title': i['title'], 'status': generic, 'statusRaw': raw_status,
                'assignee': self.primary_assignee(i),
                'description': i.get('body'), 'blockedBy': blocked_by,
                'comments': [{'id': c.get('id'), 'body': c.get('body'),
                              'createdAt': c.get('created_at'), 'updatedAt': c.get('updated_at'),
                              'revision': c.get('updated_at'),
                              'author': (c.get('user') or {}).get('login')} for c in comments],
                'labels': labels, 'updatedAt': i.get('updated_at'),
                'revision': i.get('updated_at'),
            })
        return items

class Markdown:
    def __init__(self):
        configured = PM_CONFIG.get('MARKDOWN_ROOT') or '.workspace/task-manager'
        project_root = os.environ.get('TRACKER_PROJECT_ROOT') or os.getcwd()
        self.root = os.path.abspath(
            configured if os.path.isabs(configured) else os.path.join(project_root, configured))

    @staticmethod
    def lexical_components(path):
        drive, tail = os.path.splitdrive(os.path.abspath(path))
        anchor = drive + os.path.sep
        return anchor, [part for part in tail.split(os.path.sep) if part]

    def reject_symlink_components(self, path, feature_id):
        current, parts = self.lexical_components(path)
        for part in parts:
            current = os.path.join(current, part)
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                # The regular missing-file path produces the clearer andon in
                # load/open. No later component can exist below a missing one.
                break
            except OSError as e:
                die("cannot inspect Markdown feature path '%s': %s — andon" % (feature_id, e))
            if stat.S_ISLNK(info.st_mode):
                die("Markdown feature path contains a symlinked component: %s" % current)

    @staticmethod
    def has_parent_reference(path):
        _drive, tail = os.path.splitdrive(str(path))
        separators = re.escape(os.path.sep + (os.path.altsep or ''))
        return any(part == '..' for part in re.split('[%s]' % separators, tail))

    def contained_path(self, feature_id):
        try:
            feature_path = os.fspath(feature_id)
        except TypeError:
            die("invalid Markdown feature path")
        if not isinstance(feature_path, str) or '\x00' in feature_path:
            die("invalid Markdown feature path")
        if self.has_parent_reference(feature_path):
            die("Markdown feature path escapes MARKDOWN_ROOT: %s" % feature_id)
        root = os.path.abspath(self.root)
        path = os.path.abspath(feature_path)
        try:
            inside = os.path.commonpath([root, path]) == root
        except ValueError:
            inside = False
        if not inside:
            die("Markdown feature path escapes MARKDOWN_ROOT: %s" % feature_id)
        # Check the lexical path before any resolution. A symlink that happens
        # to point back inside MARKDOWN_ROOT is still untrusted indirection.
        self.reject_symlink_components(root, feature_id)
        self.reject_symlink_components(path, feature_id)
        return path

    @staticmethod
    def open_directory_fd(path):
        current_fd = None
        anchor, parts = Markdown.lexical_components(path)
        flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        try:
            current_fd = os.open(anchor, flags)
            for part in parts:
                next_fd = os.open(part, flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except Exception:
            if current_fd is not None:
                os.close(current_fd)
            raise

    def parent_fd(self, feature_id):
        path = self.contained_path(feature_id)
        relative = os.path.relpath(path, self.root)
        parts = relative.split(os.path.sep)
        if relative == '.' or not parts[-1]:
            die("Markdown feature path must name a regular file: %s" % feature_id)
        directory_fd = self.open_directory_fd(self.root)
        flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            return directory_fd, parts[-1], path
        except Exception:
            os.close(directory_fd)
            raise

    def load(self, feature_id):
        directory_fd = file_fd = None
        try:
            directory_fd, leaf, _path = self.parent_fd(feature_id)
            file_fd = os.open(
                leaf, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) |
                getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory_fd)
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                die("Markdown feature is not a regular file: %s" % feature_id)
            with os.fdopen(file_fd, encoding='utf-8') as f:
                file_fd = None
                return f.read()
        except OSError as e:
            die("cannot read feature file '%s': %s — andon" % (feature_id, e))
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if directory_fd is not None:
                os.close(directory_fd)

    def save(self, feature_id, text):
        directory_fd = temp_fd = None
        temp_name = None
        try:
            directory_fd, leaf, _path = self.parent_fd(feature_id)
            existing = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(existing.st_mode):
                die("refusing to write a symlinked Markdown feature: %s" % feature_id)
            if not stat.S_ISREG(existing.st_mode):
                die("Markdown feature is not a regular file: %s" % feature_id)
            mode = stat.S_IMODE(existing.st_mode)
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0))
            for attempt in range(32):
                candidate = '.agent-squad-%d-%d-%d.tmp' % (
                    os.getpid(), time.time_ns(), attempt)
                try:
                    temp_fd = os.open(candidate, flags, 0o600, dir_fd=directory_fd)
                    temp_name = candidate
                    break
                except FileExistsError:
                    continue
            if temp_fd is None:
                die("cannot allocate a private temporary Markdown feature file — andon")
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                temp_fd = None
                f.write(text)
                f.flush()
                os.fchmod(f.fileno(), mode)
                os.fsync(f.fileno())
            os.replace(temp_name, leaf, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            temp_name = None
            os.fsync(directory_fd)
        except OSError as e:
            die("cannot write feature file '%s': %s — andon" % (feature_id, e))
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            if temp_name is not None and directory_fd is not None:
                try:
                    os.unlink(temp_name, dir_fd=directory_fd)
                except OSError:
                    pass
            if directory_fd is not None:
                os.close(directory_fd)

    @staticmethod
    def split_task_id(task_id):  # "<feature.md path>#<n>" -> (path, n)
        if '#' not in str(task_id):
            die("Markdown taskId must be '<feature-file>#<task-number>' (e.g. .workspace/task-manager/2026-07-06-x/feature.md#2)")
        path, _, num = str(task_id).rpartition('#')
        if not num.isdigit():
            die("bad Markdown task number '%s'" % num)
        return path, num

    @staticmethod
    def progress_comment_id(path, num):
        identity = '%s#%s' % (os.path.abspath(path), num)
        return 'managed-progress-' + hashlib.sha256(identity.encode()).hexdigest()[:20]

    @staticmethod
    def next_comment_revision(text):
        existing = [int(value) for value in re.findall(
            r'<!-- agent-squad:comment-revision:([0-9]+) -->', text)]
        return max([time.time_ns()] + [value + 1 for value in existing])

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

    def current_labels(self, task_id):
        path, num = self.split_task_id(task_id)
        text = self.load(path)
        match = self.section_pattern(num).search(text)
        if not match:
            die("no task %s in %s — andon" % (num, path))
        start = match.start()
        next_match = re.search(r'^## [0-9]+ ', text[match.end():], re.M)
        end = match.end() + next_match.start() if next_match else len(text)
        labels = re.search(r'^\*\*Labels:\*\*\s*(.*)$', text[start:end], re.M)
        if not labels or labels.group(1).strip() in ('', '-', '—'):
            return []
        return [item.strip() for item in labels.group(1).split(',') if item.strip()]

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
        if marker in (
            '[product-approval]', '[product-pushback]',
            '[resume-review]', '[resume-plan]', '[dependency-hold]',
            '[design-approved]', '[design-pushback]',
        ) or body.startswith('[DENIED ACTION]'):
            # The release gate parses an exact structured envelope, and a
            # denied-action audit record must keep its marker literal. Preserve
            # both byte-for-byte (apart from Markdown quote prefixes) instead of
            # folding the first field into the legacy dated first line.
            quoted = '\n'.join('> %s' % line for line in body.split('\n'))
        else:
            quoted = '> %s (%s): %s' % (marker, date.today().isoformat(), lines[0])
            for extra in lines[1:]:
                quoted += '\n> %s' % extra
        rest = text[m.end():]
        nxt = re.search(r'^## ', rest, re.M)
        insert_at = m.end() + (nxt.start() if nxt else len(rest))
        revision = '<!-- agent-squad:comment-revision:%d -->' % self.next_comment_revision(text)
        block = text[:insert_at].rstrip('\n') + '\n\n' + revision + '\n' + quoted + '\n\n'
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
        quoted = ('<!-- agent-squad:comment-revision:%d -->\n' %
                  self.next_comment_revision(text))
        quoted += '\n'.join('> ' + line for line in body.splitlines())
        updated = replace_managed_block(section, 'progress', quoted)
        self.save(path, text[:m.end()] + updated + (rest[nxt.start():] if nxt else ''))
        return self.progress_comment_id(path, num)

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
            progress_start = '<!-- agent-squad:progress:start -->'
            progress_end = '<!-- agent-squad:progress:end -->'
            progress_pattern = re.compile(
                re.escape(progress_start) + r'.*?' + re.escape(progress_end), re.S)
            progress_matches = list(progress_pattern.finditer(section))
            if (section.count(progress_start) != section.count(progress_end) or
                    len(progress_matches) != section.count(progress_start)):
                die("Markdown task %s has unmatched managed progress markers — andon" % num)
            if len(progress_matches) > 1:
                die("Markdown task %s has duplicate managed progress blocks — andon" % num)
            am = re.search(r'^\*\*Assignee:\*\* (.*)$', section, re.M)
            bb = re.search(r'^\*\*BlockedBy:\*\* (.*)$', section, re.M)
            lm = re.search(r'^\*\*Labels:\*\* (.*)$', section, re.M)
            blocked_by = ['%s#%s' % (feature_id, n.strip().lstrip('#'))
                          for n in bb.group(1).split(',') if n.strip()] if bb else []
            labels = ([label.strip() for label in lm.group(1).split(',') if label.strip()]
                      if lm and lm.group(1).strip() not in ('-', '—') else [])
            _blocks, _cur, _cur_revision, _offset = [], [], None, 0
            for _raw_line in section.splitlines(keepends=True):
                _l = _raw_line.rstrip('\r\n')
                _q = re.match(r'^> (.*)$', _l)
                if _q:
                    if _cur_revision is None:
                        # Markdown is append-only and has no authenticated edit
                        # timestamp. Position inside the task section is therefore
                        # its one authoritative total order. In particular, a manually
                        # appended finding must remain newer than earlier
                        # adapter-written comments whose private revision marker
                        # may contain a much larger nanosecond value.
                        _cur_revision = _offset
                    _cur.append(_q.group(1))
                elif _cur:
                    _b = '\n'.join(_cur).strip()
                    if _b: _blocks.append((_b, _cur_revision))
                    _cur, _cur_revision = [], None
                _offset += len(_raw_line)
            if _cur:
                _b = '\n'.join(_cur).strip()
                if _b: _blocks.append((_b, _cur_revision))
            description_lines, managed = [], False
            for _l in section.split('\n'):
                if re.fullmatch(r'<!-- agent-squad:comment-revision:[0-9]+ -->', _l):
                    continue
                if _l.startswith('<!-- agent-squad:') and _l.endswith(':start -->'):
                    managed = True
                    continue
                if managed:
                    if _l.startswith('<!-- agent-squad:') and _l.endswith(':end -->'):
                        managed = False
                    continue
                if _l.startswith('> ') or re.match(r'^\*\*(Assignee|BlockedBy|Labels):\*\*', _l):
                    continue
                description_lines.append(_l)
            description = re.sub(r'\n{3,}', '\n\n', '\n'.join(description_lines)).strip()
            comments = []
            for _comment_index, (_b, _revision) in enumerate(_blocks, start=1):
                _comment_id = (
                    self.progress_comment_id(feature_id, num) if _b.startswith('[progress]')
                    else 'markdown-comment-%s-%d-%s' % (
                        num, _comment_index, hashlib.sha256(_b.encode()).hexdigest()[:12]
                    )
                )
                comments.append({
                    'id': _comment_id, 'body': _b, 'createdAt': None,
                    'updatedAt': None, 'revision': 'markdown-offset:%s' % _revision,
                    'author': None,
                })
            comments.sort(key=lambda comment: (
                sortable_value(comment['revision'],
                               "Markdown task %s comment" % num),
                comment['id']))
            tasks.append({'taskId': '%s#%s' % (feature_id, num), 'title': title,
                          'status': generic_of(raw), 'statusRaw': raw,
                          'assignee': (am.group(1).strip() if am and am.group(1).strip() not in ('-', '—') else None),
                          'description': description, 'comments': comments,
                          'blockedBy': blocked_by, 'labels': labels,
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
if ADAPTER in BACKENDS:
    backend = BACKENDS[ADAPTER]()
else:
    if not re.match(r'^[A-Za-z][A-Za-z0-9_-]{0,63}$', ADAPTER):
        die("custom adapter name must match [A-Za-z][A-Za-z0-9_-]{0,63}")
    backend_root = os.path.join(SKILL_DIR, 'extensions', 'tracker-backends')
    custom_backend = os.path.join(backend_root, ADAPTER + '.py')
    for component in (
            os.path.join(SKILL_DIR, 'extensions'),
            backend_root,
            custom_backend):
        if os.path.islink(component):
            die("custom tracker backend path contains a symlink: %s" % component)
    try:
        backend_stat = os.stat(custom_backend)
    except OSError as e:
        die("adapter '%s' has no tracker-ops backend; expected extensions/tracker-backends/%s.py: %s"
            % (ADAPTER, ADAPTER, e))
    if not stat.S_ISREG(backend_stat.st_mode):
        die("custom tracker backend must be a regular Python file: %s" % custom_backend)
    spec = importlib.util.spec_from_file_location(
        'startup_factory_tracker_backend_' + hashlib.sha256(ADAPTER.encode()).hexdigest(),
        custom_backend,
    )
    if spec is None or spec.loader is None:
        die("cannot load custom tracker backend: %s" % custom_backend)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        backend = module.Backend({
            'adapter': ADAPTER,
            'feature_statuses': FEATURE_STATUSES,
            'operation_timeout_seconds': OPERATION_TIMEOUT,
            'pm_config': dict(PM_CONFIG),
            'skill_dir': SKILL_DIR,
            'task_statuses': TASK_STATUSES,
        })
    except Exception as e:
        die("cannot initialize custom tracker backend %s: %s" % (custom_backend, e))
    required_backend_methods = {
        'comment', 'comment_exists', 'current_feature_status', 'current_labels',
        'current_status', 'export', 'integration_comment_exists', 'scan',
        'set_assignee', 'set_feature_state', 'set_state', 'update_comment',
        'upsert_deployment', 'upsert_digest', 'upsert_progress',
    }
    missing_methods = sorted(
        name for name in required_backend_methods
        if not callable(getattr(backend, name, None))
    )
    if missing_methods:
        die("custom tracker backend is incomplete; missing methods: %s" %
            ', '.join(missing_methods))

def assert_task_not_ignored(task_id):
    ignored = ignored_task_labels_from_environment()
    if not ignored:
        return
    if not hasattr(backend, 'current_labels'):
        die("adapter '%s' cannot verify ignored labels at the mutation boundary — andon" % ADAPTER)
    labels = backend.current_labels(task_id)
    if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
        die("adapter '%s' returned malformed current labels — andon" % ADAPTER)
    if ignored.intersection(label.strip().casefold() for label in labels):
        die("task %s is labeled for human work; automated mutation is refused — andon" % task_id)

def fresh_task_status(task_id, expected=None):
    current = backend.current_status(task_id)
    if current is None:
        die("cannot reverse-map the current status of %s — andon" % task_id)
    if status_by_name(current).get('kind') == 'blocked':
        die("task %s is authoritatively [Blocked]; automated mutation is refused — andon" % task_id)
    if expected is not None and current != expected:
        die("task %s changed from expected [%s] to [%s] before mutation — andon"
            % (task_id, expected, current))
    assert_task_not_ignored(task_id)
    return current

# ---- operations ----------------------------------------------------------------
def op_state(args):
    if len(args) != 2:
        die("usage: state <taskId> <Status>")
    target = status_by_name(args[1])
    current_name = backend.current_status(args[0])
    if current_name is None:
        die("cannot reverse-map the current status of %s — andon" % args[0])
    assert_automated_task_transition(current_name, target['name'])
    if current_name != target['name']:
        current = status_by_name(current_name)
        if target['name'] not in current.get('transitions', []):
            die("illegal [task] transition [%s] → [%s] — andon" % (current_name, target['name']))
        fresh_task_status(args[0], current_name)
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
    if target.get('terminal') and os.environ.get('STARTUP_FACTORY_RELEASE_EXECUTOR') != '1':
        die("terminal [feature] transition is reserved for the isolated release executor")
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

def op_feature_reopen(args):
    if len(args) != 2:
        die("usage: feature-reopen <featureId> <Status>")
    if os.environ.get('STARTUP_FACTORY_PM_SUPERVISOR') != '1':
        die("feature-reopen is reserved for the deterministic PM supervisor")
    feature_id, target_name = args
    target = feature_status_by_name(target_name)
    if target.get('terminal') or target.get('kind') not in ('queued', 'working'):
        die("feature-reopen target must be a configured non-terminal queued/working status")
    current_name = backend.current_feature_status(feature_id)
    if current_name is None:
        die("cannot reverse-map the current [feature] status of %s — andon" % feature_id)
    if current_name == target_name:
        print("%s already reopened → [%s]" % (feature_id, target_name))
        return
    current = feature_status_by_name(current_name)
    if not current.get('terminal'):
        die("feature-reopen requires a terminal source status, observed [%s] — andon" % current_name)
    # This deliberately does not use the ordinary transition graph: completed
    # containers often have no outbound edge. The narrow broker operation is the
    # adapter-neutral reopen path, and the mutation is accepted only after an
    # exact read-back of the configured generic target.
    backend.set_feature_state(feature_id, target)
    observed = backend.current_feature_status(feature_id)
    if observed != target_name:
        die("[feature] reopen did not read back as [%s] (observed: %s) — andon" %
            (target_name, observed))
    print("%s reopened [%s] → [%s]" % (feature_id, current_name, target_name))

def op_task_reopen(args):
    if len(args) != 2:
        die("usage: task-reopen <taskId> <Status>")
    if os.environ.get('STARTUP_FACTORY_INTEGRATION_BROKER') != '1':
        die("task-reopen is reserved for the deterministic integration broker")
    task_id, target_name = args
    target = status_by_name(target_name)
    if target.get('terminal') or target.get('kind') != 'working':
        die("task-reopen target must be the configured non-terminal working status")
    current_name = backend.current_status(task_id)
    if current_name is None:
        die("cannot reverse-map the current status of %s — andon" % task_id)
    assert_automated_task_transition(current_name, target_name)
    if current_name == target_name:
        print("%s already reopened → [%s]" % (task_id, target_name))
        return
    current = status_by_name(current_name)
    if not current.get('terminal') or not current.get('requiresCommit'):
        die("task-reopen requires a commit-requiring terminal source status, observed [%s] — andon" % current_name)
    # This is deliberately narrower than ordinary `state`: only the broker may
    # reopen an integrated task after durable supersede/revert evidence exists.
    fresh_task_status(task_id, current_name)
    backend.set_state(task_id, target)
    observed = backend.current_status(task_id)
    if observed != target_name:
        die("[task] reopen did not read back as [%s] (observed: %s) — andon" %
            (target_name, observed))
    print("%s reopened [%s] → [%s]" % (task_id, current_name, target_name))

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
    fresh_task_status(args[0])
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
        working_targets = [
            name for name in init['transitions']
            if status_by_name(name).get('kind') == 'working'
        ]
        if len(working_targets) != 1:
            die("initial status '%s' has %d working transitions — pass --to <Status>"
                % (init['name'], len(working_targets)))
        to = working_targets[0]
    target = status_by_name(to)
    if to not in init['transitions']:
        die("claim must follow the board: '%s' is not in %s.transitions — andon" % (to, init['name']))
    claim_id = claim_id or ('claim-' + hashlib.sha256(('%s\0%s\0%s' % (task_id, role, to)).encode()).hexdigest()[:24])
    if not re.fullmatch(r'[A-Za-z0-9._:-]{8,128}', claim_id):
        die("invalid claim id '%s'" % claim_id)
    token = "claim-id: %s" % claim_id
    current = backend.current_status(task_id)
    if current is None:
        die("cannot reverse-map the current status of %s — andon" % task_id)
    assert_automated_task_transition(current, to)
    assert_task_not_ignored(task_id)
    if current == to and backend.comment_exists(task_id, token):
        print("%s claim %s already recorded → [%s]" % (task_id, claim_id, to))
        return
    if current != expected:
        die("claim conflict: expected [%s], observed [%s] for %s — no launch" % (expected, current, task_id))
    if not backend.comment_exists(task_id, token):
        fresh_task_status(task_id, expected)
        backend.comment(task_id, "[claim]\n%s\nrole: %s\ntarget-status: %s\n\n— dispatcher" % (token, role, to))
    if hasattr(backend, 'set_assignee'):
        fresh_task_status(task_id, expected)
        backend.set_assignee(task_id, role)
    fresh_task_status(task_id, expected)
    backend.set_state(task_id, target)
    observed = backend.current_status(task_id)
    if observed != to:
        die("claim write did not read back as [%s] (observed: %s) — no launch" % (to, observed))
    print("%s claimed by %s → [%s] (claim-id: %s)" % (task_id, role, to, claim_id))

def op_record_denial(args):
    # A guardrail DENY encountered while an agentic team or dedicated agent acts
    # on a [task] must become task-level evidence: what was attempted, by whom,
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
    current_name = backend.current_status(task_id)
    if current_name is None:
        die("cannot reverse-map the current status of %s — andon" % task_id)
    assert_automated_task_transition(current_name, term['name'])
    assert_task_not_ignored(task_id)
    if current_name != term['name']:
        current = status_by_name(current_name)
        if term['name'] not in current.get('transitions', []):
            die("integration cannot skip [%s] → [%s] — andon" % (current_name, term['name']))
        fresh_task_status(task_id, current_name)
        backend.set_state(task_id, term)
        observed = backend.current_status(task_id)
        if observed != term['name']:
            die("integration status did not read back as [%s] — andon" % term['name'])
    fresh_task_status(task_id, term['name'])
    if not backend.integration_comment_exists(task_id, commit):
        fresh_task_status(task_id, term['name'])
        backend.comment(task_id, body)
    print("%s → [%s] (commit %s)" % (task_id, term['name'], commit))

def op_export(args):
    if len(args) != 2:
        die("usage: export <featureId> <outfile>")
    feature_id, outfile = args
    tasks = backend.export(feature_id)
    if not isinstance(tasks, list):
        die("adapter returned a malformed feature export — andon")
    normalized, seen = [], set()
    ignored_labels = ignored_task_labels_from_environment()
    for index, task in enumerate(tasks):
        value = normalize_task_record(
            task, "feature export record %d" % (index + 1))
        if value['taskId'] in seen:
            die("adapter returned a duplicate task identity '%s' in feature export — andon"
                % value['taskId'])
        seen.add(value['taskId'])
        if task_has_ignored_label(value, ignored_labels):
            continue
        normalized.append(value)
    tasks = normalized
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
    if not isinstance(items, list):
        die("adapter returned a malformed board scan — andon")
    normalized, orphans, seen = [], [], set()
    ignored_labels = ignored_task_labels_from_environment()
    for index, item in enumerate(items):
        value = normalize_task_record(
            item, "board scan record %d" % (index + 1), feature_field=True)
        if value['status'] not in statuses:
            die("adapter returned an out-of-scope status '%s' for %s"
                % (value['status'], value['taskId']))
        if value['taskId'] in seen:
            die("adapter returned duplicate task identity '%s' in board scan — andon"
                % value['taskId'])
        seen.add(value['taskId'])
        if task_has_ignored_label(value, ignored_labels):
            continue
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
       'feature-reopen': op_feature_reopen, 'task-reopen': op_task_reopen,
       'claim': op_claim, 'record-denial': op_record_denial, 'integrate': op_integrate,
       'export': op_export, 'scan': op_scan}
if not ARGS or ARGS[0] not in OPS:
    die("usage: tracker-ops.sh {state|feature-state|feature-reopen|task-reopen|comment|comment-once|update-comment|upsert-progress|upsert-digest|upsert-deployment|claim|record-denial|integrate|export|scan} ...")
OPS[ARGS[0]](ARGS[1:])
PYEOF
