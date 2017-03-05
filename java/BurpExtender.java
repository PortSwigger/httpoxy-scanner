package burp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static java.util.Collections.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //
    // Implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a copy of the callbacks for later
        this.callbacks = callbacks;

        // and the helpers too
        this.helpers = callbacks.getHelpers();

        // register ourselves as a scanner check
        callbacks.registerScannerCheck(this);
    }

    //
    // Implement IScannerCheck
    //

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        // we don't do any passive scanning with this extension
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(
            IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint)
    {
        // create a context from which we can generate payloads etc.
        IBurpCollaboratorClientContext collaboratorContext =
            callbacks.createBurpCollaboratorClientContext();

        if (
                // we're only interested in header insertion points
                !isRelevantInsertionPoint(insertionPoint) ||

                // we need the collaborator to be set up with a hostname, not IP
                isCollaboratorLocationIpBased(collaboratorContext))
        {
            return null;
        }

        // generate a special collaborator payload
        String payload = collaboratorContext.generatePayload(true);

        // add a proxy prefix
        String httpPrefixedPayload = buildPayload(payload);

        // build the request and send it
        IHttpRequestResponse scanCheckRequestResponse =
            callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    buildRequest(baseRequestResponse, httpPrefixedPayload));

        // fetch any collaborator interactions that may have occurred
        List<IBurpCollaboratorInteraction> collaboratorInteractions =
            collaboratorContext.fetchCollaboratorInteractionsFor(payload);

        if (collaboratorInteractions.isEmpty())
        {
            // nothing to report
            return null;
        }

        // report an issue, providing the interaction as evidence
        return singletonList(reportIssue(
                    httpPrefixedPayload,
                    scanCheckRequestResponse,
                    collaboratorInteractions.get(0)));
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        return existingIssue.getUrl().equals(newIssue.getUrl())
            ? -1
            :  0;
    }

    private boolean isCollaboratorLocationIpBased(IBurpCollaboratorClientContext collaboratorContext)
    {
        return
            collaboratorContext
                .getCollaboratorServerLocation()
                .matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")
            || collaboratorContext
                .getCollaboratorServerLocation()
                .contains(":");
    }

    private boolean isRelevantInsertionPoint(IScannerInsertionPoint insertionPoint)
    {
        return insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER;
    }

    private String buildPayload(String interactionIdWithHostname)
    {
        return "Proxy: http://" + interactionIdWithHostname;
    }

    private byte[] buildRequest(
            IHttpRequestResponse baseRequestResponse,
            String proxyPrefixedPayload)
    {
        // figure out what headers are already on the request
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        List<String> headers = requestInfo.getHeaders();

        // remove any existing proxy headers
        stripProxyHeaders(headers);

        // and add our own
        headers.add(proxyPrefixedPayload);

        return helpers.buildHttpMessage(
                headers,
                substring(baseRequestResponse.getRequest(),
                    requestInfo.getBodyOffset()));
    }

    private void stripProxyHeaders(List<String> headers)
    {
        Iterator<String> headersIterator = headers.iterator();
        while (headersIterator.hasNext())
        {
            String header = headersIterator.next();
            if (header != null && header.toLowerCase().startsWith("proxy:"))
            {
                // we've found a proxy header, so remove it
                headersIterator.remove();
            }
        }
    }

    private IScanIssue reportIssue(
            String payload,
            IHttpRequestResponse sentRequestResponse,
            IBurpCollaboratorInteraction collaboratorInteraction)
    {
        // highlight the request
        IHttpRequestResponse[] httpMessages = new IHttpRequestResponse[]
        {
            callbacks.applyMarkers(
                    sentRequestResponse,
                    buildRequestHighlights(
                        payload,
                        sentRequestResponse),
                    emptyList())
        };

        // create a new issue
        return new HttPoxyIssue(
                sentRequestResponse.getHttpService(),
                helpers.analyzeRequest(sentRequestResponse).getUrl(),
                httpMessages,
                payload,
                collaboratorInteraction);
    }

    private List<int[]> buildRequestHighlights(
            String payload,
            IHttpRequestResponse sentRequestResponse)
    {
        List<int[]> requestHighlights = new ArrayList<int[]>();

        int startOfPayload = helpers.indexOf(
                sentRequestResponse.getRequest(),
                helpers.stringToBytes(payload),
                true,
                0,
                sentRequestResponse.getRequest().length);

        if (startOfPayload != -1)
        {
            requestHighlights.add(new int[] {
                startOfPayload, startOfPayload + payload.length()
            });
        }

        return requestHighlights;
    }

    private byte[] substring(byte[] array, int from)
    {
        int len = array.length - from;
        byte[] subArray = new byte[len];
        System.arraycopy(array, from, subArray, 0, len);
        return subArray;
    }
}
