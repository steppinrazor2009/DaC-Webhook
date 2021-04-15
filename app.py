import os
import base64
import dac_constants
import json
import threading
import gitlab
import hashlib
import hmac
from github3 import GitHub, GitHubEnterprise
from flask import Flask, request
from contentscanner import Scanner
    
class CICDScanner(Scanner):

    def __init__(self, payload):
        super().__init__("./modules", "modules.json")
        self.payload = payload
        self.results = {}

    def set_recap(self, commits, pusher, pushid):
        ret = {'sha': pushid, 'pusher': pusher, 'files_scanned': 0, 'vulnerable': 0, 'sus': 0, 'commits': commits}
        for commit in commits:
            for file in commit['results']:
                ret['files_scanned'] += 1
                ret['vulnerable'] += len(file['vulnerable'])
                ret['sus'] += len(file['sus'])
        return ret

    def get_body(self):
        body = "**Pusher:**\n`" + self.results['pusher'] + "`\n"
        body += "**Files Scanned:**\n`" + str(self.results['files_scanned']) + "`\n"
        body += "**Vulnerable Dependencies:**\n`" + str(self.results['vulnerable']) + "`\n"
        body += "**Suspicious Dependencies:**\n`" + str(self.results['sus']) + "`\n"
        
        for commit in self.results['commits']:
            body += "### Commit " + commit['id'] + "\n"
            for file in commit['results']:
                body += "#### " + file['file'] + "\n"
                if len(file['vulnerable']) > 0:
                    body += "##### Vulnerable: \n"
                    for v in file['vulnerable']:
                        body += "* `" + v + "`\n"
                if len(file['sus']) > 0:
                    body += "##### Suspicious: \n"
                    for s in file['sus']:
                        body += "* `" + s + "`\n"
                        
        return body

class GHScanner(CICDScanner):

    def __init__(self, payload, url, key):
        super().__init__(payload)
        self.client = self.get_gh_client(url, key)
        thread = threading.Thread(target=self.do_scan, args=())
        thread.daemon = True
        thread.start()
        self.repository = None

    def do_scan(self):
        owner = self.payload['repository']['owner']['login']
        repo = self.payload['repository']['name']
        commits = self.payload['commits']
        self.repository = self.client.repository(owner, repo)
        pusher = self.payload['pusher']['name']
        pushsha = self.payload['after']
        
        commits = []
        
        for commit in self.payload['commits']:
            treesha = commit['tree_id']
            commitfiles = commit['added'] + commit['modified']
            thistree = self.repository.tree(treesha)
            results = []
            for file in thistree.tree:
                if file.path in commitfiles and file.type == "blob":
                    thisblob = self.repository.blob(file.sha)
                    try:
                        content = base64.b64decode(thisblob.content).decode()
                    except:
                        content = base64.b64decode(thisblob.content).decode('ascii')
                    result = self.scan_contents(file.path, content)['result']
                    if result:
                        results.append(result)
            thiscommit = {"id": commit['id'], "results": results}
            commits.append(thiscommit)      

        self.results = self.set_recap(commits, pusher, pushsha)
        
        if self.results['vulnerable'] + self.results['sus'] > 0:
            self.results_action()
            
        return self.results

    def results_action(self):
        title = "Dazed and Confused findings for this push"
        body = self.get_body()
        self.repository.create_issue(title, body)
    
    def get_gh_client(self, url, key):
        if url:
            return GitHubEnterprise(url, token=key)
        return GitHub(token=key)        

class GLScanner(CICDScanner):

    def __init__(self, payload, url, key):
        super().__init__(payload)
        self.client = gitlab.Gitlab(url, private_token=key)
        thread = threading.Thread(target=self.do_scan, args=())
        thread.daemon = True
        thread.start()
        self.project = None

    def do_scan(self):
        pusher = self.payload['user_username']
        pushsha = self.payload['checkout_sha']  
        projectid = self.payload['project_id']
        defaultbranchname = self.payload['project']['default_branch']
        self.project = self.client.projects.get(projectid)
        
        commits = []
        for commit in self.payload['commits']:
            commitfiles = commit['added'] + commit['modified']
            items = self.project.repository_tree()
        
            results = []
            for file in items:
                if file['path'] in commitfiles and file['type'] == "blob":
                    thisblob = self.project.repository_blob(file['id'])
                    try:
                        content = base64.b64decode(thisblob['content']).decode()
                    except:
                        content = base64.b64decode(thisblob['content']).decode('ascii')
                    result = self.scan_contents(file['path'], content)['result']
                    if result:
                        results.append(result)
            thiscommit = {"id": commit['id'], "results": results}
            commits.append(thiscommit)      

        self.results = self.set_recap(commits, pusher, pushsha)
        
        if self.results['vulnerable'] + self.results['sus'] > 0:
            self.results_action()

        return self.results
    
    def results_action(self):
        title = "Dazed and Confused findings for this push"
        body = self.get_body()
        issue = self.project.issues.create({'title': title, 'description': body})

#verify secret from webhook
def get_signature(secret, payload):
    computed_hmac = hmac.new(
            key=secret.encode(),
            msg=payload,
            digestmod=hashlib.sha256,
        ).hexdigest()
    return "sha256=" + computed_hmac

GITLAB_URL = 'https://gitlab.com/'
GITLAB_TOKEN = os.environ['GITLAB_TOKEN']
GL_SECRET = os.environ['GL_SECRET']

GITHUB_URL = "https://github.com/" #private gh server
GITHUB_TOKEN = os.environ['GITHUB_TOKEN']
GH_SECRET = os.environ['GH_SECRET']

app = Flask(__name__)

@app.route("/gl", methods=['POST'])
#pushes from gitlab webhooks
def gl_push_event():
    payload = request.json
    event = request.headers.get('X-GitLab-Event')
    requestsignature = request.headers.get('X-Gitlab-Token')
    if event == "Push Hook" and requestsignature == GL_SECRET:
        GLScanner(payload, GITLAB_URL, GITLAB_TOKEN)
        return "Scanning..."
    return "There was a problem..."
    
@app.route("/gh", methods=['POST'])
#pushes from public github webhooks
def gh_push_event():
    payload = request.json
    event = request.headers.get('X-GitHub-Event')
    requestsignature = request.headers.get('X-Hub-Signature-256')
    signature = get_signature(GH_SECRET, request.data)
    if event == "push" and requestsignature == signature:
        GHScanner(payload, "", GITHUB_TOKEN)
        return "Scanning..."
    return "There was a problem..." 
    
@app.route("/ghe", methods=['POST'])
#pushes from private github webhooks
def ghe_push_event():
    payload = request.json
    event = request.headers.get('X-GitHub-Event')
    requestsignature = request.headers.get('X-Hub-Signature-256')
    signature = get_signature(GH_SECRET, request.data)
    if event == "push" and requestsignature == signature:
        GHScanner(payload, GITHUB_URL, GITHUB_TOKEN)
        return "Scanning..."
    return "There was a problem..."     