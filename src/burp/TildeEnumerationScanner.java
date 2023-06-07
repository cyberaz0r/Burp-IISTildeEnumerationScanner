package burp;

import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.awt.Color;
import java.awt.Font;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextPane;

class TildeEnumerationScanner extends Thread {
	private volatile boolean interrupting;
	private enum ScanStatus {IN_PROGRESS, INTERRUPTING, INTERRUPTED, DONE};
	private String targetUrl;
	private Output output;
	private Output tempOutput;
	private Config config;
	private Requester requester;
	private Bruteforcer bruteforcer;
	private Thread vulnerableCheckThread;
	private JButton scanButton;
	private String requestMethod;
	private String magicFinalPart;
	private HashMap<String, String> statusPaths;
	private IHttpRequestResponse[] vulnerableRequests;
	private IBurpExtenderCallbacks callbacks;
	private SitemapCompleteFilenameGuesser sitemapFileNameGuesser;
	private WordlistCompleteFilenameGuesser wordlistFileNameGuesser;
	private long startScanTime;
	private long startBruteTime;

	public TildeEnumerationScanner(String targetUrl, Config config, Output output, JButton scanButton, IBurpExtenderCallbacks callbacks) {
		this.targetUrl = targetUrl;
		this.config = config;
		this.output = output;
		this.scanButton = scanButton;
		this.callbacks = callbacks;
		bruteforcer = null;
		wordlistFileNameGuesser = null;
		sitemapFileNameGuesser = null;
		vulnerableCheckThread = null;
		vulnerableRequests = null;
		interrupting = false;
	}

	@Override
	public void interrupt() {
		if (interrupting)
			return;

		// set interrupting flag to avoid executing the interruption more than once
		interrupting = true;

		// disable scan button, update status label and print interruption waiting message
		updateScanUI(ScanStatus.INTERRUPTING);

		// send interrupt signal to this thread
		super.interrupt();

		// get a reference to this thread
		Thread reference = this;

		// start an asynchronous task to interrupt all tasks that might be running
		CompletableFuture<Void> interruptTask = CompletableFuture.runAsync(() -> {
			// interrupt vulnerable check thread and wait for it to gracefully stop
			if (vulnerableCheckThread != null && vulnerableCheckThread.isAlive()) {
				vulnerableCheckThread.interrupt();
				while (vulnerableCheckThread.isAlive()) {
					try {
						Thread.sleep(500);
					}
					catch (InterruptedException e) {
						return;
					}
				}
			}

			// interrupt bruteforcer master thread and wait for it to gracefully stop
			if (bruteforcer != null && bruteforcer.isAlive()) {
				bruteforcer.interrupt();
				while (bruteforcer.isAlive()) {
					try {
						Thread.sleep(500);
					}
					catch (InterruptedException e) {
						return;
					}
				}
			}

			// interrupt wordlist filename guesser thread and wait for it to gracefully stop
			if (wordlistFileNameGuesser != null && wordlistFileNameGuesser.isAlive()) {
				wordlistFileNameGuesser.interrupt();
				while (wordlistFileNameGuesser.isAlive()) {
					try {
						Thread.sleep(500);
					}
					catch (InterruptedException e) {
						return;
					}
				}
			}

			// interrupt sitemap filename guesser thread and wait for it to gracefully stop
			if (sitemapFileNameGuesser != null && sitemapFileNameGuesser.isAlive()) {
				sitemapFileNameGuesser.interrupt();
				while (sitemapFileNameGuesser.isAlive()) {
					try {
						Thread.sleep(500);
					}
					catch (InterruptedException e) {
						return;
					}
				}
			}

			// and finally wait for the main thread to gracefully stop by using its reference
			while (reference.isAlive()) {
				try {
					Thread.sleep(500);
				}
				catch (InterruptedException e) {
					return;
				}
			}
		});

		// once finished all interruption tasks, enable back scan button
		interruptTask.thenRun(() -> updateScanUI(ScanStatus.INTERRUPTED));
	}

	@Override
	public void run() {
		// update scan button and status label
		updateScanUI(ScanStatus.IN_PROGRESS);

		try {
			// checking for valid URL
			if (targetUrl.length() < 8 || (!targetUrl.substring(0, 7).equals("http://") && !targetUrl.substring(0, 8).equals("https://"))) {
				throw new InterruptedException("[X] Error: invalid URL \"" + targetUrl + "\"");
			}

			// checking for correct number of threads
			if (config.getNThreads() < 1 || config.getNThreads() > 9999) {
				throw new InterruptedException("[X] Error: number of threads must be between 1 and 9999");
			}

			// checking for correct request format
			if (!config.getRequestString().endsWith("\n\n")) {
				throw new InterruptedException("[X] Error: request format is incorrect");
			}

			// checking for correct length of user-defined filename and extension prefixes
			if (config.getNameStartsWith().length() > 6) {
				throw new InterruptedException("[X] Error: short names can start with 6 characters maximum");
			}

			if (config.getExtStartsWith().length() > 3) {
				throw new InterruptedException("[X] Error: short name extensions can start with 3 characters maximum");
			}

			// checking for complete filename guessing wordlist files existence (if complete filename wordlist guessing is enabled)
			if (config.getCompleteFileGuessWordlist()) {
				if (!config.getFileNameWordlist().exists() || !config.getFileExtWordlist().exists()) {
					throw new InterruptedException("[X] Error: Wordlist-based complete filename guessing requires a wordlist of file names and a wordlist for file extensions, the provided wordlist files do not exist");
				}
			}

			startScanTime = System.currentTimeMillis();
			output.print("[+] Started scan for URL \"" + targetUrl + "\"\n");

			// initialize requester object
			requester = new Requester(targetUrl + config.getUrlSuffix(), config.getDelay(), callbacks);

			// initialize and start thread for checking if the host is vulnerable
			vulnerableCheckThread = new Thread(isVulnerable());
			vulnerableCheckThread.start();

			// wait for the check to finish
			while (vulnerableCheckThread.isAlive()) {
				try {
					if (interrupting) {
						vulnerableCheckThread.interrupt();
						return;
					}
					Thread.sleep(500);
				}
				catch (InterruptedException e) {
					return;
				}
			}

			// if the host is not vulnerable or no short name was found, the vulnerable requests array will stay null after the check
			if (vulnerableRequests == null) {
				output.print("[-] Host \"" + targetUrl + "\" seems to be not vulnerable or no short name was found");
				output.print("\n[+] Scan completed in " + ((System.currentTimeMillis() - startScanTime)/1000L) + " seconds\n[+] Requests sent: " + requester.getReqCounter());
				updateScanUI(ScanStatus.DONE);
				return;
			}

			// if it is, the vulnerable requests array will contain the valid and invalid name requests
			output.print("\n[+] Host \"" + targetUrl + "\" is vulnerable!");
			output.print("[+] Used HTTP method: " + requestMethod + "\n[+] Suffix (magic part): " + magicFinalPart);

			// add an issue if not present
			try {
				ScanIssue issue = new ScanIssue(requester.getHttpService(), targetUrl, vulnerableRequests);
				if (!Utils.checkExistingIssue(issue, callbacks))
					callbacks.addScanIssue(issue);
			}
			catch (Exception e) {
				output.printStderr("Error: could not add issue to Burp Suite, maybe the extension is running in the Community Edition that does not support this feature");
			}

			// if in check mode, print number of requests performed and end scan
			if (!config.getExploitMode()) {
				output.print("\n[+] Scan completed in " + ((System.currentTimeMillis() - startScanTime)/1000L) + " seconds\n[+] Requests sent: " + requester.getReqCounter());
				output.status("Scan completed");
				updateScanUI(ScanStatus.DONE);
				return;
			}

			// if in exploit mode, perform multithreaded bruteforce of files and directories
			output.print("\n[*] Starting filename and directory bruteforce on \"" + targetUrl + "\"");

			// preparing request format
			String requestFormat = config.getRequestString().replace("§METHOD§", requestMethod).replace("\n", "\r\n");

			// initializing bruteforcer and starting bruteforce
			bruteforcer = new Bruteforcer(config, output, requester, requestFormat, magicFinalPart, statusPaths);
			startBruteTime = System.currentTimeMillis();
			bruteforcer.start();

			// waiting the bruteforcer to finish
			while (bruteforcer.isAlive()) {
				try {
					if (interrupting) {
						bruteforcer.interrupt();
						return;
					}
					Thread.sleep(500);
				}
				catch (InterruptedException e) {
					return;
				}
			}

			output.print("\n[+] Bruteforce completed in " + ((System.currentTimeMillis() - startBruteTime)/1000L) + " seconds");
			output.print("[+] Total time elapsed: " + ((System.currentTimeMillis() - startScanTime)/1000L) + " seconds\n[+] Requests sent: " + requester.getReqCounter());

			// print directories found, if any, in a tree structure and parse them to detect possible/actual directory names
			if (bruteforcer.getDirsFound().isEmpty()) {
				output.print("\n[-] No directories found");
			}
			else {
				output.print("\n[+] Identified directories: " + bruteforcer.getDirsFound().size());
				for (String dirFound : bruteforcer.getDirsFound()) {
					output.print(Utils.tree(dirFound, 1));
					if (dirFound.lastIndexOf("~") < 6) {
						if (dirFound.lastIndexOf("~") == 5 && dirFound.matches(".*(\\w\\d|\\d\\w).*")) {
							output.print(Utils.tree("Possible directory name = " + dirFound.substring(0, dirFound.lastIndexOf("~")), 2));
						}
						else {
							output.print(Utils.tree("Actual directory name = " + dirFound.substring(0, dirFound.lastIndexOf("~")), 2));
						}
					}
				}
			}

			// print files found, if any, in a tree structure and parse them to detect possible/actual file names and actual extensions
			if (bruteforcer.getFilesFound().isEmpty()) {
				output.print("\n[-] No files found");
			}
			else {
				output.print("\n[+] Identified files: " + bruteforcer.getFilesFound().size());
				for (String fileFound : bruteforcer.getFilesFound()) {
					String currentName = fileFound;
					String currentExt = "";

					output.print(Utils.tree(fileFound, 1));

					if (fileFound.length() - fileFound.lastIndexOf(".") <= 3) {
						currentName = fileFound.substring(0, fileFound.lastIndexOf("."));
						currentExt = fileFound.substring(fileFound.lastIndexOf("."));
					}

					if (currentName.lastIndexOf("~") < 6) {	
						if (currentName.lastIndexOf("~") == 5 && fileFound.matches("^[a-fA-F0-9]{5}.*")) {
							output.print(Utils.tree("Possible file name = " + fileFound.substring(0, currentName.lastIndexOf("~")), 2));
						}
						else {
							output.print(Utils.tree("Actual file name = " + fileFound.substring(0, currentName.lastIndexOf("~")), 2));
						}
					}

					if (fileFound.length() - fileFound.lastIndexOf(".") <= 3) {
						output.print(Utils.tree("Actual extension = " + currentExt, 2));
					}
				}
			}

			// complete filename guessing from sitemap
			if (config.getCompleteFileGuessSitemap()) {
				output.status("Generating complete filename list");
				output.print("\n[*] Generating Intruder payload list for complete filename guessing using sitemap");

				// initializing sitemap filename guesser and starting guessing
				sitemapFileNameGuesser = new SitemapCompleteFilenameGuesser(bruteforcer.getDirsFound(), bruteforcer.getFilesFound(), requester.getHttpService().getProtocol()+"://"+requester.getHttpService().getHost(), callbacks);
				sitemapFileNameGuesser.start();

				// waiting the sitemap filename guesser to finish
				while (sitemapFileNameGuesser.isAlive()) {
					try {
						if (interrupting) {
							sitemapFileNameGuesser.interrupt();
							return;
						}
						Thread.sleep(500);
					}
					catch (InterruptedException e) {
						return;
					}
				}

				if (sitemapFileNameGuesser.getPayloads().size() == 0) {
					output.print("[-] No matches with scan results found in sitemap, Intruder payload list for complete filename guessing using sitemap will not be generated...");
				}
				else {
					// removing old sitemap filename guesser from Intruder if exists
					for (IIntruderPayloadGeneratorFactory generator : callbacks.getIntruderPayloadGeneratorFactories()) {
						if (generator.getGeneratorName().equals(sitemapFileNameGuesser.getGeneratorName())) {
							callbacks.removeIntruderPayloadGeneratorFactory(generator);
						}
					}

					// registering new sitemap filename guesser and sending tab to Intruder
					callbacks.registerIntruderPayloadGeneratorFactory(sitemapFileNameGuesser);
					Utils.sendToIntruder(callbacks, config.getRequestString(), requester.getHttpService().getHost(), requester.getBasePath(), requester.getHttpService().getPort(), requester.getHttpService().getProtocol().equals("https"));

					output.print("[+] Generated " + sitemapFileNameGuesser.getPayloads().size() + " possible complete filenames from sitemap, switch to Intruder to launch a guessing attack using the generated filenames");
				}
			}

			// complete filename guessing from user-provided wordlists
			if (config.getCompleteFileGuessWordlist()) {
				output.status("Generating complete filename list");
				output.print("\n[*] Generating Intruder payload list for complete filename guessing using wordlists");

				// initializing wordlist filename guesser and starting guessing
				wordlistFileNameGuesser = new WordlistCompleteFilenameGuesser(bruteforcer.getDirsFound(), bruteforcer.getFilesFound(), config.getFileNameWordlist(), config.getFileExtWordlist());
				wordlistFileNameGuesser.start();

				// waiting the wordlist filename guesser to finish
				while (wordlistFileNameGuesser.isAlive()) {
					try {
						if (interrupting) {
							wordlistFileNameGuesser.interrupt();
							return;
						}
						Thread.sleep(500);
					}
					catch (InterruptedException e) {
						return;
					}
				}

				if (wordlistFileNameGuesser.getPayloads().size() == 0) {
					output.print("[-] No matches with scan results found in wordlists, Intruder payload list for complete filename guessing using wordlists will not be generated...");
				}
				else {
					// removing old wordlist filename guesser from Intruder if exists
					for (IIntruderPayloadGeneratorFactory generator : callbacks.getIntruderPayloadGeneratorFactories()) {
						if (generator.getGeneratorName().equals(wordlistFileNameGuesser.getGeneratorName())) {
							callbacks.removeIntruderPayloadGeneratorFactory(generator);
						}
					}

					// registering new wordlist filename guesser and sending tab to Intruder
					callbacks.registerIntruderPayloadGeneratorFactory(wordlistFileNameGuesser);
					Utils.sendToIntruder(callbacks, config.getRequestString(), requester.getHttpService().getHost(), requester.getBasePath(), requester.getHttpService().getPort(), requester.getHttpService().getProtocol().equals("https"));

					output.print("[+] Generated " + wordlistFileNameGuesser.getPayloads().size() + " possible complete filenames from wordlists, switch to Intruder to launch a guessing attack using the generated filenames");
				}
			}
			// once finished, toggle scan/stop button and reset UI to ready to scan
			updateScanUI(ScanStatus.DONE);
		}
		catch (InterruptedException e) {
			// handle incorrect fields errors
			if (e.getMessage().startsWith("[X] Error: ")) {
				output.print(e.getMessage());
				updateScanUI(ScanStatus.DONE);
			}
			return;
		}
		catch (RuntimeException e) {
			output.print("[X] Error: " + e.getMessage() + "\n[i] Check the stack trace in the extension errors tab for more details.");
			output.printStackTrace(e);
			output.status("Scan error");
			interrupt();
			return;
		}
	}

	// update UI style based on scan status
	private void updateScanUI(ScanStatus scanStatus) {
		switch (scanStatus) {
			case IN_PROGRESS:
				// update status label
				output.status("Scan in progress");

				// toggle scan button to "stop"
				scanButton.setBackground(null);
				scanButton.setForeground(null);
				scanButton.setFont(null);
				scanButton.setText("Stop");
				break;
			case INTERRUPTING:
				// disable scan button until termination and update status label
				scanButton.setEnabled(false);
				output.status("Scan interrupting");
				output.print("[*] Interrupting scan...");

				// reset output to avoid spam printing due to interruption
				tempOutput = output;
				output = new Output(new JTextPane(), new JLabel(), callbacks);
				break;
			case INTERRUPTED:
				// reset output to the original one
				output = tempOutput;

				// notify graceful interruption on UI
				output.print("[-] Scan interrupted");
			case DONE:
				output.status("Ready to scan");

				// reset scan button style and enable it
				scanButton.setBackground(new Color(249, 130, 11));
				scanButton.setForeground(Color.WHITE);
				scanButton.setFont(new Font("Nimbus", Font.BOLD, 14));
				scanButton.setText("Scan");
				scanButton.setEnabled(true);
				break;
		}
	}

	private Runnable isVulnerable() {
		return new Runnable() {
			@Override
			public void run() {
				for (String finalPart : config.getMagicFinalPartList()) {
					for (String method : config.getRequestMethods()) {
						if (isInterrupted())
							return;

						output.print("[*] Trying method \"" + method + "\" with magic final part \"" + finalPart + "\"");

						// initialize request paths HashMap to find invalid status messages
						statusPaths = new HashMap<String, String>();
						statusPaths.put("validName", config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+finalPart);
						statusPaths.put("invalidName", "1234567890"+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+finalPart);
						statusPaths.put("invalidDifferentName", "0123456789"+config.getAsteriskSymbol()+"~1."+config.getAsteriskSymbol()+finalPart);
						statusPaths.put("invalidNameExtension", "0123456789"+config.getAsteriskSymbol()+"~1.1234"+config.getAsteriskSymbol()+finalPart);
						statusPaths.put("invalidExtension", config.getAsteriskSymbol()+"~1.1234"+config.getAsteriskSymbol()+finalPart);
						statusPaths.put("invalidNameNoExtension", "1234567890"+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+finalPart);
						statusPaths.put("invalidNameNoExtensionNoQuestionmark", "1234567890"+config.getAsteriskSymbol()+"~1"+config.getQuestionMarkSymbol()+finalPart);
						statusPaths.put("invalidNameNoExtensionQuestionmark", new String(new char[10]).replace("\0", config.getQuestionMarkSymbol())+"~1"+config.getAsteriskSymbol()+finalPart);
						statusPaths.put("invalidNameNoSpecialchars", "1234567890"+"~1.1234"+finalPart);

						// valid name (twice to strip out dynamic values)
						IHttpRequestResponse validNameRequest1 = requester.httpRequestRaw(config.getRequestString().replace("§METHOD§", method).replace("§PATH§", requester.getBasePath() + Utils.urlEncode(statusPaths.get("validName")) + requester.getQueryString()).replace("\n", "\r\n"));
						IHttpRequestResponse validNameRequest2 = requester.httpRequestRaw(config.getRequestString().replace("§METHOD§", method).replace("§PATH§", requester.getBasePath() + Utils.urlEncode(statusPaths.get("validName")) + requester.getQueryString()).replace("\n", "\r\n"));
						String validNameResponse = new ResponseDifference(new String(validNameRequest1.getResponse()), new String(validNameRequest2.getResponse())).getStripped();

						// invalid name (twice to strip out dynamic values)
						IHttpRequestResponse invalidNameRequest1 = requester.httpRequestRaw(config.getRequestString().replace("§METHOD§", method).replace("§PATH§", requester.getBasePath() + Utils.urlEncode(statusPaths.get("invalidName")) + requester.getQueryString()).replace("\n", "\r\n"));
						IHttpRequestResponse invalidNameRequest2 = requester.httpRequestRaw(config.getRequestString().replace("§METHOD§", method).replace("§PATH§", requester.getBasePath() + Utils.urlEncode(statusPaths.get("invalidName")) + requester.getQueryString()).replace("\n", "\r\n"));
						String invalidNameResponse = new ResponseDifference(new String(invalidNameRequest1.getResponse()), new String(invalidNameRequest2.getResponse())).getStripped();

						// checking for differences between valid and invalid filenames responses
						if (new ResponseDifference(validNameResponse, invalidNameResponse).getDifferences().length() > config.getDeltaResponseLength()) {
							String invalidDifferentNameRequest1 = requester.httpRequest(config.getRequestString().replace("§METHOD§", method).replace("§PATH§", requester.getBasePath() + Utils.urlEncode(statusPaths.get("invalidDifferentName")) + requester.getQueryString()).replace("\n", "\r\n"));
							String invalidDifferentNameRequest2 = requester.httpRequest(config.getRequestString().replace("§METHOD§", method).replace("§PATH§", requester.getBasePath() + Utils.urlEncode(statusPaths.get("invalidDifferentName")) + requester.getQueryString()).replace("\n", "\r\n"));
							String invalidDifferentNameResponse = new ResponseDifference(invalidDifferentNameRequest1, invalidDifferentNameRequest2).getStripped();

							// if two different invalid requests lead to different responses, we cannot rely on them unless their difference is negligible!
							if (new ResponseDifference(invalidDifferentNameResponse, invalidNameResponse).getDifferences().length() <= config.getDeltaResponseLength()) {
								// host is vulnerable! set class vars and exit
								vulnerableRequests = new IHttpRequestResponse[] {validNameRequest1, invalidNameRequest1};
								magicFinalPart = finalPart;
								requestMethod = method;
								return;
							}
						}
					}
				}
			}
		};
	}
}