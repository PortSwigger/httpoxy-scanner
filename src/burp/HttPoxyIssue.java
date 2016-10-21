package burp;

import java.net.URL;

class HttPoxyIssue implements IScanIssue
{
    private static final int EXTENSION_GENERATED_ISSUE_TYPE = 0x08000000;

    private static final String ISSUE_NAME = "Server-side proxy settings overwrite (HTTPoxy)";
    private static final String SEVERITY = "High";
    private static final String CONFIDENCE = "Certain";

    private static final String ISSUE_BACKGROUND =
            "HTTPoxy is a vulnerability that arises when the application reads the Proxy header value from an HTTP request," +
                    " saves it to the HTTP_PROXY environment variable, and outgoing HTTP requests made by the server use it to proxy those requests.<br><br>" +
                    "An attacker can use this behavior to redirect requests made by the application to a server under the attacker's control. " +
                    "They can also cause the server to initiate connections to hosts that are not directly accessible by the attacker, such as those on internal systems behind a firewall. " +
                    "For more information, refer to <a href=\"https://httpoxy.org\">HTTPoxy</a>.<br><br>";

    private static final String REMEDIATION_BACKGROUND =
            "The server should block the Proxy header in HTTP requests as it does not have any legitimate purpose. " +
                    "In most cases, updating the software used in the application stack should fix the issue.";

    private final URL url;
    private final String detail;
    private final IHttpService httpService;
    private final IHttpRequestResponse[] httpMessages;

    HttPoxyIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String payload, IBurpCollaboratorInteraction collaboratorInteraction)
    {
        this.url = url;
        this.httpService = httpService;
        this.httpMessages = httpMessages;
        this.detail = buildIssueDetail(payload, collaboratorInteraction);
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return ISSUE_NAME;
    }

    @Override
    public int getIssueType()
    {
        return EXTENSION_GENERATED_ISSUE_TYPE;
    }

    @Override
    public String getSeverity()
    {
        return SEVERITY;
    }

    @Override
    public String getConfidence()
    {
        return CONFIDENCE;
    }

    @Override
    public String getIssueBackground()
    {
        return ISSUE_BACKGROUND;
    }

    @Override
    public String getRemediationBackground()
    {
        return REMEDIATION_BACKGROUND;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

    private String buildIssueDetail(String payload, IBurpCollaboratorInteraction event)
    {
        return "The application is vulnerable to HTTPoxy attacks.<br><br>" +
                "The header <strong>" + payload + "</strong> was sent to the application.<br><br>" +
                "The application made " + eventDescription(event) + "<strong>" + event.getProperty("interaction_id") + "</strong>.<br><br>" +
                "The  " + interactionType(event.getProperty("type")) + " was received from the IP address " + event.getProperty("client_ip") +
                " at " + event.getProperty("time_stamp") + ".";
    }

    private String interactionType(String type)
    {
        if (type.equalsIgnoreCase("http"))
        {
            return "HTTP connection";
        }
        else if (type.equalsIgnoreCase("dns"))
        {
            return "DNS lookup";
        }
        else
        {
            return "interaction";
        }
    }

    private String eventDescription(IBurpCollaboratorInteraction event)
    {
        if (event.getProperty("type").equalsIgnoreCase("http"))
        {
            return "an <strong>HTTP</strong> request to the Collaborator server using the subdomain ";
        }
        else if (event.getProperty("type").equalsIgnoreCase("dns"))
        {
            return "a <strong>DNS</strong> lookup of type <strong>" + event.getProperty("query_type") + "</strong> to the Collaborator server subdomain ";
        }
        else
        {
            return "an unknown interaction with the Collaborator server using the subdomain ";
        }
    }
}
