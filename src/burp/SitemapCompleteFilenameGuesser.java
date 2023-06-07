package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Collections;

class SitemapCompleteFilenameGuesser extends Thread implements IIntruderPayloadGeneratorFactory {
	private IBurpExtenderCallbacks callbacks;
	private List<String> intruderPayloads;
	private List<String> filesFound;
	private List<String> dirsFound;
	private String targetUrl;

	public SitemapCompleteFilenameGuesser(List<String> dirsFound, List<String> filesFound, String targetUrl, IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.filesFound = filesFound;
		this.dirsFound = dirsFound;
		this.targetUrl = targetUrl;
	}

	public List<String> getPayloads() {
		return intruderPayloads;
	}

	@Override
	public String getGeneratorName() {
		return "IISTildeEnumeration - sitemap-based full filename guessing";
	}

	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
		return new IntruderPayloadGenerator(intruderPayloads);
	}

	@Override
	public void run() {
		IHttpRequestResponse[] sitemap = callbacks.getSiteMap(targetUrl);
		List<String> elementsFound = Utils.buildElementList(dirsFound, filesFound);
		List<String> possibleFileNames = new ArrayList<String>();
		List<String> possibleFileExts = new ArrayList<String>();

		// iterate through sitemap to get URL paths
		for (IHttpRequestResponse requestResponse : sitemap) {
			String urlPath = callbacks.getHelpers().analyzeRequest(requestResponse).getUrl().getPath();
			for (String pathElem : urlPath.split("/")) {
				// get filename and extension from every path element in URL and add them to lists
				String pathName = pathElem.indexOf(".") != -1 ? pathElem.substring(0, pathElem.lastIndexOf('.')).toUpperCase() : pathElem.toUpperCase();
				String pathExt = pathElem.indexOf(".") != -1 ? pathElem.substring(pathElem.lastIndexOf('.')).toUpperCase() : "";
				possibleFileNames.add(pathName);
				possibleFileExts.add(pathExt);
			}
		}

		// remove duplicates from scan results
		possibleFileNames = new ArrayList<String>(new LinkedHashSet<String>(possibleFileNames));
		possibleFileExts = new ArrayList<String>(new LinkedHashSet<String>(possibleFileExts));

		// generate payloads
		intruderPayloads = new ArrayList<String>();
		for (String name : possibleFileNames) {
			for (String elem : elementsFound) {
				// check if thread has been interrupted, and in case stop looping
				if (isInterrupted())
					return;
				List<String> matches = Utils.findMatches(elem, name, possibleFileExts);
				intruderPayloads.addAll(matches);
			}
		}

		// remove duplicates from the payload list and sort it
		intruderPayloads = new ArrayList<String>(new LinkedHashSet<>(intruderPayloads));
		Collections.sort(intruderPayloads);
	}
}