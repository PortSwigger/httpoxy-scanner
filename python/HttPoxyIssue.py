from burp import IScanIssue

EXTENSION_GENERATED_ISSUE_TYPE = 0x08000000

ISSUE_NAME = "Server-side proxy settings overwrite (HTTPoxy)"
SEVERITY = "High"
CONFIDENCE = "Certain"

ISSUE_BACKGROUND = \
        "HTTPoxy is a vulnerability that arises when the application reads the Proxy header value from an HTTP request," + \
                " saves it to the HTTP_PROXY environment variable, and outgoing HTTP requests made by the server use it to proxy those requests.<br><br>" + \
                "An attacker can use this behavior to redirect requests made by the application to a server under the attacker's control. " + \
                "They can also cause the server to initiate connections to hosts that are not directly accessible by the attacker, such as those on internal systems behind a firewall. " + \
                "For more information, refer to <a href=\"https://httpoxy.org\">HTTPoxy</a>.<br><br>"

REMEDIATION_BACKGROUND = \
        "The server should block the Proxy header in HTTP requests as it does not have any legitimate purpose. " + \
                "In most cases, updating the software used in the application stack should fix the issue."

def interaction_type(type):
    if type.lower() == "http":
        return "HTTP connection"
    elif type.lower() == "dns":
        return "DNS lookup"
    else:
        return "interaction"

def build_issue_detail(payload, event):
    return "The application is vulnerable to HTTPoxy attacks.<br><br>" + \
            "The header <strong>" + payload + "</strong> was sent to the application.<br><br>" + \
            "The application made " + event_description(event) + "<strong>" + event.getProperty("interaction_id") + "</strong>.<br><br>" + \
            "The  " + interaction_type(event.getProperty("type")) + " was received from the IP address " + event.getProperty("client_ip") + \
            " at " + event.getProperty("time_stamp") + "."

def event_description(event):
    if event.getProperty("type").lower() == "http":
        return "an <strong>HTTP</strong> request to the Collaborator server using the subdomain "
    elif event.getProperty("type").lower() == "dns":
        return "a <strong>DNS</strong> lookup of type <strong>" + event.getProperty("query_type") + "</strong> to the Collaborator server subdomain "
    else:
        return "an unknown interaction with the Collaborator server using the subdomain "

class HttPoxyIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, payload, collaborator_interaction):
        self._url = url
        self._http_service = http_service
        self._http_messages = http_messages
        self._detail = build_issue_detail(payload, collaborator_interaction)

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return ISSUE_NAME

    def getIssueType(self):
        return EXTENSION_GENERATED_ISSUE_TYPE

    def getSeverity(self):
        return SEVERITY

    def getConfidence(self):
        return CONFIDENCE

    def getIssueBackground(self):
        return ISSUE_BACKGROUND

    def getRemediationBackground(self):
        return REMEDIATION_BACKGROUND

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service
