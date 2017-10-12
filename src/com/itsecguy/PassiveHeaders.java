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

    private List<IScanIssue> testHeader(IHttpRequestResponse requestResponse, Test test)
    {
        //List<String> mimes = Arrays.asList(test.checks.mimes);
        List<String> headers = this.helpers.analyzeResponse(requestResponse.getResponse()).getHeaders();
        Short status = this.helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode();
        
        //mimes.toString().toLowerCase().matches("\\[.*\\b" + mime.toLowerCase() + "\\b.*]")
        if(!headers.toString().toLowerCase().contains(test.checks.check.toLowerCase()) && status == 200)
        {
            //String mime = this.helpers.analyzeResponse(requestResponse.getResponse()).getStatedMimeType();

            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(utility.new ScanIssue(requestResponse,
                    test.name,
                    test.severity,
                    test.confidence,
                    test.background,
                    test.detail,
                    test.remediation));
            return issues;
        }
        return null;
    }

    private List<Test> getTests()
    {
        Reader reader = new InputStreamReader(getClass().getResourceAsStream("/tests.json"));
        Gson gson = new Gson();
        Test[] tests = gson.fromJson(reader, Test[].class);

        return Arrays.asList(tests);
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse)
    {
        List<Test> tests = getTests();
        List<IScanIssue> issues = new ArrayList<>(1);

        tests.forEach((test) -> {
            issues.addAll(testHeader(requestResponse, test));
        });
        return issues;
    }

    private class Test
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