package com.itsecguy;

import burp.BurpUtilities;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import com.google.gson.Gson;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PassiveHeaders
{
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final BurpUtilities utility;

    public PassiveHeaders(BurpUtilities utility)
    {
        this.utility = utility;
        this.callbacks = this.utility.getCallbacks();
        this.helpers = this.callbacks.getHelpers();
    }

    // Perform each check.
    private List<IScanIssue> doHeaderChecks(IHttpRequestResponse requestResponse, HeaderCheck check)
    {
        List<String> headers = this.helpers.analyzeResponse(requestResponse.getResponse()).getHeaders();
        
        // Check the MIME types.
        boolean goodMime = true;
        List<String> mimes = Arrays.asList(check.checks.mimes);
        String mime = this.helpers.analyzeResponse(requestResponse.getResponse()).getStatedMimeType();
        if(!mimes.isEmpty() && mime != null)
        {
            goodMime = mimes.toString().toLowerCase().contains(mime.toLowerCase());
        }
        
        // Create issue if header is missing and an allowed MIME.
        if(!headers.toString().toLowerCase().contains(check.checks.check.toLowerCase())
                && goodMime)
        {
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(utility.new ScanIssue(requestResponse,
                    check.name,
                    check.severity,
                    check.confidence,
                    check.background,
                    check.detail,
                    check.remediation));
            return issues;
        }
        return null;
    }

    // Import the header checks from imbedded JSON.
    private List<HeaderCheck> getHeaderChecks()
    {
        Reader reader = new InputStreamReader(getClass().getResourceAsStream("/headers.json"));
        Gson gson = new Gson();
        HeaderCheck[] checks = gson.fromJson(reader, HeaderCheck[].class);

        return Arrays.asList(checks);
    }

    // Loop through each check and execute them.
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse)
    {
        List<HeaderCheck> checks = getHeaderChecks();
        List<IScanIssue> issues = new ArrayList<>(1);
        List<String> headers = this.helpers.analyzeResponse(requestResponse.getResponse()).getHeaders();
        
        // Ignore none 200 responses
        if (this.utility.getStatusCode(requestResponse) != 200)
            return issues;
        
        // Ignore responses with no content length
        if (this.utility.getContentLength(headers) == 0)
            return issues;
        
        checks.forEach((check) -> {
            List<IScanIssue> issue = doHeaderChecks(requestResponse, check);
            if(issue != null) { issues.addAll(issue); }
        });
        return issues;
    }

    private class HeaderCheck
    {
        public String name;
        public String severity;
        public String confidence;
        public String background;
        public String detail;
        public String remediation;
        public Checks checks;
    }

    private class Checks
    {
        public String[] mimes;
        public String check;
    }
}