java_import 'burp.IBurpExtender'
java_import 'burp.IScannerCheck'
java_import 'burp.IScannerInsertionPoint'

IPV4 = /^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$/

require_relative 'HttPoxyIssue'

def is_collaborator_location_ip_based(collaborator_context)
  IPV4.match(collaborator_context.getCollaboratorServerLocation()) or \
    collaborator_context.getCollaboratorServerLocation().include? ":"
end

def is_relevant_insertionPoint(insertion_point)
  insertion_point.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER
end

def build_payload(interaction_id_with_hostname)
  "Proxy: http://" + interaction_id_with_hostname
end

def strip_proxy_headers(headers)
  headers.select { |h| not h.downcase.start_with? "proxy:" }
end


class BurpExtender
  include IBurpExtender, IScannerCheck

  #
  # Implement IBurpExtender
  #

  def registerExtenderCallbacks(callbacks)
    # keep a copy of the callbacks for later
    @callbacks = callbacks

    # and the helpers too
    @helpers = callbacks.getHelpers

    # register ourselves as a scanner check
    callbacks.registerScannerCheck self
  end

  #
  # Implement IScannerCheck
  #

  def doPassiveScan(base_request_response)
    # we don't do any passive scanning with this extension
    nil
  end

  def doActiveScan(base_request_response, insertion_point)
    # create a context from which we can generate payloads etc.
    collaborator_context = @callbacks.createBurpCollaboratorClientContext

    # we're only interested in header insertion points
    # we need the collaborator to be set up with a hostname, not IP
    if (not is_relevant_insertionPoint insertion_point) or \
        is_collaborator_location_ip_based collaborator_context
      return nil
    end

    # generate a special collaborator payload
    payload = collaborator_context.generatePayload true

    # add a proxy prefix
    http_prefixed_payload = build_payload payload

    # build the request and send it
    scan_check_request_response = \
      @callbacks.makeHttpRequest(
          base_request_response.getHttpService,
          self.build_request(base_request_response, http_prefixed_payload))

    # fetch any collaborator interactions that may have occurred
    collaborator_interactions = \
      collaborator_context.fetchCollaboratorInteractionsFor payload

    if collaborator_interactions.length == 0
      # nothing to report
      return nil
    end

    # report an issue, providing the interaction as evidence
    return [self.report_issue(
          http_prefixed_payload,
          scan_check_request_response,
          collaborator_interactions[0])]
  end

  def consolidateDuplicateIssues(existing_issue, new_issue)
    if existing_issue.getUrl == new_issue.getUrl
      -1
    else
      0
    end
  end


  def build_request(base_request_response, proxy_prefixed_payload)
    # figure out what headers are already on the request
    request_info = @helpers.analyzeRequest base_request_response
    headers = request_info.getHeaders

    # remove any existing proxy headers
    strip_proxy_headers headers

    # and add our own
    headers.add proxy_prefixed_payload

    return @helpers.buildHttpMessage(
        headers,
        base_request_response.getRequest()[request_info.getBodyOffset()..-1])
  end

  def report_issue(payload, sent_request_response, collaborator_interaction)
    # highlight the request
    http_messages = [@callbacks.applyMarkers(
          sent_request_response,
          self.build_request_highlights(
            payload,
            sent_request_response),
          [])]

    # create a new issue
    return HttPoxyIssue.new(
        sent_request_response.getHttpService(),
        @helpers.analyzeRequest(sent_request_response).getUrl(),
        http_messages,
        payload,
        collaborator_interaction)
  end

  def build_request_highlights(payload, sent_request_response)
    request_highlights = []

    start_of_payload = @helpers.indexOf(
        sent_request_response.getRequest(),
        @helpers.stringToBytes(payload),
        true,
        0,
        sent_request_response.getRequest().length)

    if start_of_payload != -1
      request_highlights.push([
        start_of_payload, start_of_payload + payload.length
      ].to_java :int)
    end

    return request_highlights
  end
end
