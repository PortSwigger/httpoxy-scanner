from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScannerInsertionPoint

from jarray import array
import re

IPV4 = re.compile("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")

from HttPoxyIssue import HttPoxyIssue

def is_collaborator_location_ip_based(collaborator_context):
    return \
        IPV4.match(collaborator_context \
            .getCollaboratorServerLocation()) \
        or ":" in collaborator_context \
            .getCollaboratorServerLocation()

def is_relevant_insertionPoint(insertion_point):
    return insertion_point.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER

def build_payload(interaction_id_with_hostname):
    return "Proxy: http://" + interaction_id_with_hostname

def strip_proxy_headers(headers):
    return [h for h in headers if not h.lower().startswith("proxy:")]


class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # Implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a copy of the callbacks for later
        self._callbacks = callbacks

        # and the helpers too
        self._helpers = callbacks.getHelpers()

        # register ourselves as a scanner check
        callbacks.registerScannerCheck(self)

    #
    # Implement IScannerCheck
    #

    def doPassiveScan(self, base_request_response):
        # we don't do any passive scanning with this extension
        pass

    def doActiveScan(self, base_request_response, insertion_point):
        # create a context from which we can generate payloads etc.
        collaborator_context = self._callbacks.createBurpCollaboratorClientContext()

        # we're only interested in header insertion points
        # we need the collaborator to be set up with a hostname, not IP
        if (not is_relevant_insertionPoint(insertion_point)) or \
                is_collaborator_location_ip_based(collaborator_context):
            return None

        # generate a special collaborator payload
        payload = collaborator_context.generatePayload(True)

        # add a proxy prefix
        http_prefixed_payload = build_payload(payload)

        # build the request and send it
        scan_check_request_response = \
            self._callbacks.makeHttpRequest(
                    base_request_response.getHttpService(),
                    self._build_request(base_request_response, http_prefixed_payload))

        # fetch any collaborator interactions that may have occurred
        collaborator_interactions = \
            collaborator_context.fetchCollaboratorInteractionsFor(payload)

        if len(collaborator_interactions) == 0:
            # nothing to report
            return None

        # report an issue, providing the interaction as evidence
        return [self._report_issue(
                    http_prefixed_payload,
                    scan_check_request_response,
                    collaborator_interactions[0])]

    def consolidateDuplicateIssues(self, existing_issue, new_issue):
        return -1 if existing_issue.getUrl() == new_issue.getUrl() else 0


    def _build_request(self, base_request_response, proxy_prefixed_payload):
        # figure out what headers are already on the request
        request_info = self._helpers.analyzeRequest(base_request_response)
        headers = request_info.getHeaders()

        # remove any existing proxy headers
        strip_proxy_headers(headers)

        # and add our own
        headers.add(proxy_prefixed_payload)

        return self._helpers.buildHttpMessage(
                headers,
                base_request_response.getRequest()[request_info.getBodyOffset():])

    def _report_issue(self, payload, sent_request_response, collaborator_interaction):
        # highlight the request
        http_messages = [self._callbacks.applyMarkers(
                    sent_request_response,
                    self._build_request_highlights(
                        payload,
                        sent_request_response),
                    [])]

        # create a new issue
        return HttPoxyIssue(
                sent_request_response.getHttpService(),
                self._helpers.analyzeRequest(sent_request_response).getUrl(),
                http_messages,
                payload,
                collaborator_interaction)

    def _build_request_highlights(self, payload, sent_request_response):
        request_highlights = []

        start_of_payload = self._helpers.indexOf(
                sent_request_response.getRequest(),
                self._helpers.stringToBytes(payload),
                True,
                0,
                len(sent_request_response.getRequest()))

        if start_of_payload != -1:
            request_highlights.append(array([
                start_of_payload, start_of_payload + len(payload)
            ], 'i'))

        return request_highlights
