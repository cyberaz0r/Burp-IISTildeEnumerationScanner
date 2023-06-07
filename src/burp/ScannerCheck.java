package burp;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;

public class ScannerCheck implements IScannerCheck{
	private IBurpExtenderCallbacks callbacks;

	public ScannerCheck(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getUrl().toString().equals(newIssue.getUrl().toString()))
			return -1;
		return 0;
	}

	// active scan: check for vulnerability by testing default hardcoded values, for advanced check and exploitation there's the GUI scanner
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		// initializing vars
		List<IScanIssue> result = new ArrayList<IScanIssue>();
		Requester requester = new Requester(baseRequestResponse, baseRequestResponse.getHttpService(), callbacks);
		String[] reqLines = new String(baseRequestResponse.getRequest()).split("\r\n");
		String[] firstLine = reqLines[0].split(" ");
		String basePath = (firstLine[1].endsWith("/")) ? firstLine[1].substring(0, firstLine[1].length() - 1) : firstLine[1];
		String baseRequest = "§METHOD§ §PATH§ " + String.join(" ", Arrays.copyOfRange(firstLine, 2, firstLine.length)) + "\r\n" + String.join("\r\n", Arrays.copyOfRange(reqLines, 1, reqLines.length));

		// looping through hardcoded request methods and magic final parts
		for (String magicFinalPart : "/~1/.rem,/~1/,\\a.aspx,\\a.asp,/a.aspx,/a.asp,/a.shtml,/a.asmx,/a.ashx,/a.config,/a.php,/a.jpg,/webresource.axd,/a.xxx".split(",")) {
			for (String requestMethod : "OPTIONS,POST,DEBUG,TRACE,GET,HEAD".split(",")) {
				String validName = basePath + "/" + Utils.urlEncode("*~1*" + magicFinalPart);
				String invalidName = basePath + "/1234567890" + Utils.urlEncode("*~1*" + magicFinalPart);
				String invalidDifferentName = basePath + "/0123456789" + Utils.urlEncode("*~1.*" + magicFinalPart);

				// valid name (twice to strip out dynamic values)
				IHttpRequestResponse validNameRequest1 = requester.httpRequestRaw(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", validName));
				IHttpRequestResponse validNameRequest2 = requester.httpRequestRaw(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", validName));
				String validNameResponse = new ResponseDifference(new String(validNameRequest1.getResponse()), new String(validNameRequest2.getResponse())).getStripped();

				// invalid name (twice to strip out dynamic values)
				IHttpRequestResponse invalidNameRequest1 = requester.httpRequestRaw(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", invalidName));
				IHttpRequestResponse invalidNameRequest2 = requester.httpRequestRaw(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", invalidName));
				String invalidNameResponse = new ResponseDifference(new String(invalidNameRequest1.getResponse()), new String(invalidNameRequest2.getResponse())).getStripped();

				// checking for differences between valid and invalid filenames responses
				if (new ResponseDifference(validNameResponse, invalidNameResponse).getDifferences().length() > 75) {
					String invalidDifferentNameRequest1 = requester.httpRequest(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", invalidDifferentName));
					String invalidDifferentNameRequest2 = requester.httpRequest(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", invalidDifferentName));
					String invalidDifferentNameResponse = new ResponseDifference(invalidDifferentNameRequest1, invalidDifferentNameRequest2).getStripped();

					// if two different invalid requests lead to different responses, we cannot rely on them unless their difference is negligible!
					if (new ResponseDifference(invalidDifferentNameResponse, invalidNameResponse).getDifferences().length() <= 75) {
						// host is vulnerable, adding issue if not present
						IHttpRequestResponse[] vulnerableRequests = {validNameRequest1, invalidNameRequest1};
						String vulnerableUrl = baseRequestResponse.getHttpService().getProtocol() + "://" + baseRequestResponse.getHttpService().getHost() + basePath;
						ScanIssue issue = new ScanIssue(requester.getHttpService(), vulnerableUrl, vulnerableRequests);
						if (!Utils.checkExistingIssue(issue, callbacks)) {
							result.add(issue);
							return result;
						}
						// if vulnerable but issue already present, there is no need to continue scan, stopping it
						return null;
					}
				}
			}
		}
		return null;
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		return null;
	}
}
