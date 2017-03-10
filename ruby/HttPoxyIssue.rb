java_import 'burp.IScanIssue'

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

def interaction_type(type)
  if type.downcase == "http"
    return "HTTP connection"
  elsif type.downcase == "dns"
    return "DNS lookup"
  else
    return "interaction"
  end
end

def build_issue_detail(payload, event)
  return "The application is vulnerable to HTTPoxy attacks.<br><br>" + \
      "The header <strong>" + payload + "</strong> was sent to the application.<br><br>" + \
      "The application made " + event_description(event) + "<strong>" + event.getProperty("interaction_id") + "</strong>.<br><br>" + \
      "The  " + interaction_type(event.getProperty("type")) + " was received from the IP address " + event.getProperty("client_ip") + \
      " at " + event.getProperty("time_stamp") + "."
end

def event_description(event)
  if event.getProperty("type").downcase == "http"
    return "an <strong>HTTP</strong> request to the Collaborator server using the subdomain "
  elsif event.getProperty("type").downcase == "dns"
    return "a <strong>DNS</strong> lookup of type <strong>" + event.getProperty("query_type") + "</strong> to the Collaborator server subdomain "
  else
    return "an unknown interaction with the Collaborator server using the subdomain "
  end
end

class HttPoxyIssue
  include IScanIssue

  def initialize(http_service, url, http_messages, payload, collaborator_interaction)
    @url = url
    @http_service = http_service
    @http_messages = http_messages
    @detail = build_issue_detail payload, collaborator_interaction
  end

  def getUrl()
    @url
  end

  def getIssueName()
    ISSUE_NAME
  end

  def getIssueType()
    EXTENSION_GENERATED_ISSUE_TYPE
  end

  def getSeverity()
    SEVERITY
  end

  def getConfidence()
    CONFIDENCE
  end

  def getIssueBackground()
    ISSUE_BACKGROUND
  end

  def getRemediationBackground()
    REMEDIATION_BACKGROUND
  end

  def getIssueDetail()
    @detail
  end

  def getRemediationDetail()
    nil
  end

  def getHttpMessages()
    @http_messages
  end

  def getHttpService()
    @http_service
  end
end
