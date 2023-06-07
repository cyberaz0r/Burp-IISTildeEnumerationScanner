package burp;

import java.util.Arrays;
import java.util.List;

class Requester {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private IHttpService httpService;
	private String hostname;
	private String basePath;
	private String queryString;
	private int reqCounter;
	private int delayValue;
	private int msSinceLastReq;

	public Requester(String targetUrl, int delayValue, IBurpExtenderCallbacks callbacks) {
		// get callbacks and helpers
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();

		// initialize request counter
		reqCounter = 0;

		// extract request information from URL string
		String hostname = targetUrl.split("://")[1].split("\\?")[0].split("/")[0];
		String path = targetUrl.split("://")[1].replace(hostname, "").split("\\?")[0];
		boolean useHttps = targetUrl.substring(0, 5).equals("https");
		int port = (hostname.indexOf(":") != -1) ? Integer.parseInt(hostname.split(":")[1]) : ((useHttps) ? 443 : 80);

		this.msSinceLastReq = 0;
		this.delayValue = delayValue;
		this.hostname = hostname;
		this.basePath = path.endsWith("/") ? path : path+"/";
		this.queryString = targetUrl.indexOf('?')>0 ? "?"+targetUrl.split("\\?")[1] : "";

		// initialize IHttpService object
		this.httpService = helpers.buildHttpService(hostname.split(":")[0], port, useHttps);
	}

	public Requester(IHttpRequestResponse baseRequestResponse, IHttpService httpService, IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();

		// extract hostname, base path and querystring from request in IHttpRequestResponse object
		String[] request = new String(baseRequestResponse.getRequest()).split("\r\n");
		String[] pathAndQuerystring = request[0].split(" ")[1].split("\\?", 2);

		this.delayValue = 0;
		this.httpService = httpService;
		this.basePath = pathAndQuerystring[0].endsWith("/") ? pathAndQuerystring[0] : pathAndQuerystring[0]+"/";
		this.queryString = pathAndQuerystring.length>1 ? "?"+pathAndQuerystring[1] : "";
		this.hostname = request[1].split("Host: ")[1];
	}

	public IHttpService getHttpService() {
		return httpService;
	}

	public String getQueryString() {
		return queryString;
	}

	public String getBasePath() {
		return basePath;
	}

	public int getReqCounter() {
		return reqCounter;
	}

	public IHttpRequestResponse httpRequestRaw(String requestString) {
		try {
			// increment request counter
			this.reqCounter++;

			// initialize request byte array
			byte[] request = requestString.replace("§HOST§", hostname).getBytes();

			// parse request headers and body from text
			IRequestInfo requestInfo = helpers.analyzeRequest(request);
			List<String> headers = requestInfo.getHeaders();
			byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);

			// build request
			request = helpers.buildHttpMessage(headers, body);

			// delay request if needed
			if (delayValue > 0) {
				while (msSinceLastReq < delayValue) {
					try {
						Thread.sleep(1);
						msSinceLastReq++;
					}
					catch (InterruptedException e) {
						return null;
					}
				}
				msSinceLastReq = 0;
			}

			// send request
			IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(httpService, request);

			// return request object
			return requestResponse;
		}
		catch (RuntimeException e) {
			throw new RuntimeException("connection error");
			//throw new RuntimeException(e.toString());
		}
	}

	public String httpRequest(String requestString) {
		return new String(httpRequestRaw(requestString).getResponse());
	}
}