package burp;

import com.itsecguy.PassiveHeaders;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpUtilities implements IScannerCheck
{
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public BurpUtilities(BurpExtender extension)
    {
        this.callbacks = extension.getCallbacks();
        this.helpers = this.callbacks.getHelpers();
    }

    // Passive scan
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse)
    {
        PassiveHeaders passive = new PassiveHeaders(this);
        return passive.doPassiveScan(requestResponse);
    }

    // Active scan (not used)
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse requestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    // Consolidate duplicate issues based on name and url.
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        boolean names = existingIssue.getIssueName().equals(newIssue.getIssueName());
        boolean urls = existingIssue.getUrl().equals(newIssue.getUrl());

        if(names && urls)
        {
            return -1;
        }
        return 0;
    }
    
    // Returns the oddsets of any matches for highlighting.
    public List<int[]> getOffsets(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<>();
        for (int i = 0; i < response.length; i += match.length)
        {
            i = this.helpers.indexOf(response, match, true, i, response.length);
            if (i == -1)
                break;
            matches.add(new int[] { i, i + match.length });
        }
        return matches;
    }
    
    // Return content length value.
    public int getContentLength(List<String> headers)
    {
        for (String header: headers)
        {
            if (header.toLowerCase().startsWith("content-length"))
            {
                String length = header.toLowerCase().split(" ")[1];
                return Integer.parseInt(length);
            }
        }
        return 0;
    }
    
    // Return HTTP status code.
    public short getStatusCode(IHttpRequestResponse requestResponse)
    {
        return this.helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode();
    }

    // Implimentation of custom scanner issue.
    public class ScanIssue implements IScanIssue
    {
        private final IHttpRequestResponse requestResponse;
        private final String name;
        private final String severity;
        private final String confidence;
        private final String issueBackground;
        private final String issueDetail;
        private final String remediationBackground;
        private final String remediationDetail;
        private final int type;

        public ScanIssue(IHttpRequestResponse requestResponse,
                         String name,
                         String severity,
                         String confidence,
                         String issueBackground,
                         String issueDetail,
                         String remediationDetail)
        {
            this.requestResponse = requestResponse;
            this.name = name;
            this.severity = severity;
            this.confidence = confidence;
            this.issueBackground = issueBackground;
            this.issueDetail = issueDetail;
            this.remediationBackground = null;
            this.remediationDetail = remediationDetail;
            this.type = 0x0800000;
        }

        @Override
        public String getProtocol()
        {
            return requestResponse.getProtocol();
        }

        @Override
        public String getHost()
        {
            return requestResponse.getHost();
        }

        @Override
        public int getPort()
        {
            return requestResponse.getPort();
        }

        @Override
        public URL getUrl()
        {
            return BurpUtilities.this.helpers.analyzeRequest(requestResponse).getUrl();
        }

        @Override
        public String getIssueName()
        {
            return this.name;
        }

        @Override
        public int getIssueType()
        {
            return this.type;
        }

        @Override
        public String getSeverity()
        {
            return this.severity;
        }

        @Override
        public String getConfidence()
        {
            return this.confidence;
        }

        @Override
        public String getIssueBackground()
        {
            return this.issueBackground;
        }

        @Override
        public String getRemediationBackground()
        {
            return this.remediationBackground;
        }

        @Override
        public String getIssueDetail()
        {
            return this.issueDetail;
        }

        @Override
        public String getRemediationDetail()
        {
            return this.remediationDetail;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages()
        {
            IHttpRequestResponse[] messages = { this.requestResponse };
            return messages;
        }

        @Override
        public IHttpService getHttpService()
        {
            return this.requestResponse.getHttpService();
        }
    }

    public IBurpExtenderCallbacks getCallbacks()
    {
        return this.callbacks;
    }
}