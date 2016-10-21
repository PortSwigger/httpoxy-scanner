package burp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static burp.IScannerInsertionPoint.*;
import static java.util.Collections.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        burpHelpers = callbacks.getHelpers();
        callbacks.registerScannerCheck(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        return emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        if (!isRelevantInsertionPoint(insertionPoint) || isCollaboratorLocationIpBased(collaboratorContext))
        {
            return emptyList();
        }

        String payload = collaboratorContext.generatePayload(true);
        String httpPrefixedPayload = buildPayload(payload);
        byte[] request = buildRequest(baseRequestResponse, httpPrefixedPayload);

        IHttpRequestResponse scanCheckRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);

        List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(payload);
        if (collaboratorInteractions.isEmpty())
        {
            return emptyList();
        }

        return singletonList(reportIssue(httpPrefixedPayload, scanCheckRequestResponse, collaboratorInteractions.get(0)));
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        return existingIssue.getUrl().equals(newIssue.getUrl()) ? -1 : 0;
    }

    private boolean isCollaboratorLocationIpBased(IBurpCollaboratorClientContext collaboratorContext)
    {
        return collaboratorContext.getCollaboratorServerLocation().matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}") || collaboratorContext.getCollaboratorServerLocation().contains(":");
    }

    private boolean isRelevantInsertionPoint(IScannerInsertionPoint insertionPoint)
    {
        return insertionPoint.getInsertionPointType() == INS_HEADER;
    }

    private String buildPayload(String interactionIdWithHostname)
    {
        return "Proxy: http://" + interactionIdWithHostname;
    }

    private byte[] buildRequest(IHttpRequestResponse baseRequestResponse, String payload)
    {
        IRequestInfo requestInfo = burpHelpers.analyzeRequest(baseRequestResponse);
        List<String> headers = requestInfo.getHeaders();
        Iterator<String> headersIterator = headers.iterator();
        while (headersIterator.hasNext())
        {
            String header = headersIterator.next();
            if (header != null && header.toLowerCase().startsWith("proxy:"))
            {
                headersIterator.remove();
            }
        }
        headers.add(payload);

        return burpHelpers.buildHttpMessage(headers, substring(baseRequestResponse.getRequest(), requestInfo.getBodyOffset()));
    }

    private IScanIssue reportIssue(String payload, IHttpRequestResponse sentRequestResponse, IBurpCollaboratorInteraction collaboratorInteraction)
    {
        IHttpRequestResponse[] httpMessages = new IHttpRequestResponse[]{callbacks.applyMarkers(sentRequestResponse, buildRequestHighlights(payload, sentRequestResponse), Collections.<int[]>emptyList())};

        return new HttPoxyIssue(sentRequestResponse.getHttpService(), burpHelpers.analyzeRequest(sentRequestResponse).getUrl(), httpMessages, payload, collaboratorInteraction);
    }

    private List<int[]> buildRequestHighlights(String payload, IHttpRequestResponse sentRequestResponse)
    {
        List<int[]> requestHighlights = new ArrayList<int[]>();

        int startOfPayload = burpHelpers.indexOf(sentRequestResponse.getRequest(), burpHelpers.stringToBytes(payload), true, 0, sentRequestResponse.getRequest().length);
        if (startOfPayload != -1)
        {
            requestHighlights.add(new int[]{startOfPayload, startOfPayload + payload.length()});
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
