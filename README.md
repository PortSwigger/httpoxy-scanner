# Sample Burp Suite extension: Collaborator interactions

This example uses the [HTTPoxy](https://httpoxy.org/) vulnerability to
illustrate use of the Burp Collaborator. We generate URLs for a vulnerable
application to request, and find the vulnerability by asking the Collaborator
for interactions with those URLs.

A collaborator context is used to generate payloads and we send these in a Proxy
header during an active scan.

This example uses a simple server whose only task is to request URLs sent in
Proxy headers. It does not replicate the actual vulnerability but instead
prefers to be a simple illustration of the interactions that might occur with
the collaborator.

This repository includes source code for Java, Python and Ruby. It also includes
a server (for NodeJS) to test the scan on.

After loading the extension, you'll need to simply active scan the local server.
