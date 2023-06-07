package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.net.URLEncoder;
import javax.swing.JFileChooser;
import javax.swing.JTextPane;
import javax.swing.JTextField;

class Utils {
	// function to send a request to Intruder with a fixed insertion point
	public static void sendToIntruder(IBurpExtenderCallbacks callbacks, String requestFormat, String hostname, String path, int port, boolean https) {
		int offset = new String("GET " + path).length();
		List<int[]> insertionPoints = new ArrayList<int[]>() {{ add(new int[] {offset, offset}); }};
		callbacks.sendToIntruder(hostname, port, https, requestFormat.replace("§METHOD§", "GET").replace("§HOST§", hostname).replace("§PATH§", path).replace("\n", "\r\n").getBytes(), insertionPoints);
	}

	// function that adds an issue to the Burp Scanner results if not already present
	public static boolean checkExistingIssue(IScanIssue newIssue, IBurpExtenderCallbacks callbacks) {
		for (IScanIssue existingIssue : callbacks.getScanIssues(newIssue.getUrl().toString())) {
			if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
				return true;
			}
		}
		return false;
	}

	// function to encode a string to URL format
	public static String urlEncode(String unquoted) {
		try {
			return URLEncoder.encode(unquoted, "UTF-8").replace("*", "%2A");
		}
		catch (UnsupportedEncodingException e) {
			throw new RuntimeException("unsupported encoding while URL-encoding");
		}
	}

	// function to print a tree-like structure
	public static String tree(String str, int level) {
		String dentSpace = new String(new char[level]).replace("\0", "  ");
		return dentSpace + "|_ " + str;
	}

	// function to merge elements from a list of files and directories
	public static List<String> buildElementList(List<String> dirsFound, List<String> filesFound) {
		List<String> elements = new ArrayList<String>();
		elements.addAll(dirsFound);
		elements.addAll(filesFound);
		return elements;
	}

	// function to save text output from a text pane to a file
	public static void saveOutputToFile(IBurpExtenderCallbacks callbacks, JTextPane textPane, JTextField targetUrlField) {
		// get output content
		byte[] output = textPane.getText().getBytes();

		// build filename string
		String filename =
			"IISTildeEnumScanResult_" +
			targetUrlField.getText().replace("http://", "").replace("https://", "").replace("/", "-").split("\\?")[0] +
			"_" + Long.toString(System.currentTimeMillis() / 1000L) + ".txt";

		// show save file dialog
		final JFileChooser fc = new JFileChooser();
		fc.setSelectedFile(new File(filename));

		if (fc.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
			// write file
			try {
				FileOutputStream fos = new FileOutputStream(fc.getSelectedFile());
				fos.write(output);
				fos.close();
			}
			catch (IOException e) {
				// write exception to error tabs
				PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
				e.printStackTrace(stderr);
			}
		}
	}

	// function to read a wordlist file and return its content as a list of strings
	public static List<String> readWordlist(File file) {
		final int CHUNK_SIZE = 8192;
		List<String> wordList = new ArrayList<>();

		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
			char[] buffer = new char[CHUNK_SIZE];
			StringBuilder lineBuilder = new StringBuilder();

			int charsRead;
			while ((charsRead = reader.read(buffer)) != -1) {
				for (int i = 0; i < charsRead; i++) {
					char c = buffer[i];
					// if newline character, add the line to the list and clear the StringBuilder
					if (c == '\n') {
						wordList.add(lineBuilder.toString());
						lineBuilder.setLength(0);
					} else {
						lineBuilder.append(c);
					}
				}
			}

			// add the last line if it doesn't end with a newline character
			if (lineBuilder.length() > 0) {
				wordList.add(lineBuilder.toString());
			}
		}
		catch (FileNotFoundException e) {
			return null;
		}
		catch (IOException e) {
			return null;
		}

		return wordList;
	}

	// function to find matches between a wordlist element and a scan result
	public static List<String> findMatches(String elem, String name, List<String> possibleFileExts) {
		List<String> matchList = new ArrayList<String>();
		// get basename and extension from scan results
		String elemName = elem.split("~")[0];
		String elemExt = elem.indexOf(".") != -1 ? elem.split("\\.")[1] : "";

		// if name from input list starts with the one from scan results
		if (elemName.length()<6 || name.toUpperCase().startsWith(elemName)) {
			name = (elemName.length()<6 ? elemName : name.toUpperCase());
			// find all the possible extensions for this name and add all the combinations to the final list
			if (elemExt.length() == 3) {
				List<String> elemExts = Utils.findExtensionMatches(possibleFileExts, elem.substring(elem.lastIndexOf('.') + 1));
				for (String ext : elemExts) {
					matchList.add(name + "." + ext);
				}
			}
			else {
				matchList.add(name + (!elemExt.equals("") ? "."+elemExt : ""));
			}
		}
		return matchList;
	}

	// function to find all the possible complete extensions for a given short extension
	public static List<String> findExtensionMatches(List<String> possibleFileExts, String elemExt) {
		List<String> fileExts = new ArrayList<String>();

		for (String ext : possibleFileExts) {
			// strip dot if present
			if (ext.startsWith("."))
				ext = ext.substring(1, ext.length());

			// strip querystring if present
			ext = ext.split("\\?")[0];

			// if extension from wordlist starts with the one from scan results, it is a possible extension
			if (ext.toUpperCase().startsWith(elemExt))
				fileExts.add(ext.toUpperCase());
		}

		// if no extension found, add the one from scan results
		if (fileExts.isEmpty())
			fileExts.add(elemExt);

		// remove duplicates from the list before returning it
		return new ArrayList<String>(new LinkedHashSet<>(fileExts));
	}

	// function to strip response data using regexes in order to remove all possible dynamic values from it
	public static String stripResponse(String response, String basePath, String queryString, int level) {
		// split headers and body
		String responseHeaders = response.split("\r\n\r\n")[0];
		String responseBody = "";

		// handle empty body
		try {
			responseBody = response.split("\r\n\r\n")[1];
		}
		catch (IndexOutOfBoundsException e) {}

		// strip body
		responseBody = responseBody.replaceAll("(?im)([\\\\])", "/").replaceAll("(?im)&amp;", "&").replaceAll("(?im)([\\(\\)\\.\\*\\?])", "");

		// remove incoming data + even URL-encoded format
		String remove = basePath + "/" + Utils.urlEncode(basePath) + "/?" + queryString;
		remove = remove.toLowerCase().replaceAll("(?im)([\\\\])", "/").replaceAll("(?im)&amp;", "&").replaceAll("(?im)([\\(\\)\\.\\*\\?])", "");

		// remove a tag when it includes dynamic contents
		String[] temp = remove.split("/");
		for (int i = 0; i < temp.length; i++) {
			if (temp[i].length() > 0) {
				while (responseBody.indexOf(temp[i]) > 0) {
					responseBody = responseBody.replaceAll("(?im)(\\<[^>]+[a-z0-9\\-]=['\"`]([^\"]*" + temp[i] + "[^\"]*)['\"`][^>]*>)", "");
					responseBody = responseBody.replace(temp[i], "");
				}
			}
		}

		// remove Date, Expires and Set-Cookie headers
		responseHeaders = responseHeaders.replaceAll("(?m)\r?\n(Date:.*|Set-Cookie:.*|Expires:.*)", "");
		// remove nonce attributes
		responseBody = responseBody.replaceAll("nonce=\"[a-zA-Z0-9]*\"", "");
		// removing some common .NET errors
		responseBody = responseBody.replaceAll("(?im)(((server error in).+>)|((physical path).+>)|((requested url).+>)|((handler<).+>)|((notification<).+>))","");
		// removing HTML comments
		responseBody = responseBody.replaceAll("(?im)(<!--[\\w\\W]*?-->)","");
		// removing URLs
		responseBody = responseBody.replaceAll("(\\:[\\/\\\\]+[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}([\\/\\\\]+[a-zA-Z\\/\\\\0-9%_\\-\\?=&\\.]*)?)","");

		// more granular strips in level 2+, may cause false negatives
		if (level > 1) {
			// HEADERS
			// ignore value of all headers starting with X-
			responseHeaders = responseHeaders.replaceAll("(?im)^(x\\-[^:]+:\\s*)[^\\r\\n]+$", "$1");
			// remove content-type header and its value
			responseHeaders = responseHeaders.replaceAll("(?im)^content\\-type[\\s]*[\\:\\=]+[\\s]*[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*", "");
			// remove content-length header and its replacements by WAFs
			responseHeaders = responseHeaders.replaceAll("(?im)^content\\-l[ength]{4,}[\\s]*[\\:\\=]+[\\s]*[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*", "");
			// remove more known dynamic headers and their values
			responseHeaders = responseHeaders.replaceAll("(?i)(tag|p3p|expires|date|age|modified|cookie|report\\-to)[\\s]*[\\:\\=]+[\\s]*[^\\r\\n]*", "");
			// remove headers with less complex values
			responseHeaders = responseHeaders.replaceAll("(?im)^[\\w\\d\\-]+\\s*:\\s*[\\w\\d, \\t:;=\\/]+$","");
			// BODY
			// replace d attribute value in the path tag in a SVG as they are very long and annoying!
			responseBody = responseBody.replaceAll("<path[^>]*\\sd=\"([^\"]*)\"","<path");
			// replace UUIDs
			responseBody = responseBody.replaceAll("\\b(?=[a-fA-F0-9-]{32,})(?:[a-fA-F0-9]{1,8}-?(?:[a-fA-F0-9]{1,4}-?){3}[a-fA-F0-9]{1,12})\\b","00000000000000000000000000000000");
			// replace hex strings longer than 30 characters
			responseBody = responseBody.replaceAll("\\b(?:[0-9a-fA-F]{2}){15,}\\b","A0000000000000000000000000000F");
			// replace base64 characters longer than 30 characters - this can also match a URL path, but we cannot do anything about that
			responseBody = responseBody.replaceAll("(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[=\\/\\-_+\\\\])[a-zA-Z0-9=\\/\\-_+\\\\]{30,}","ABCD");
			// replace dates with both the ISO 8601 format (2023-04-28T13:37:00Z) and the RFC 2822 format (Fri, 28 Apr 2023 13:37:00 GMT)
			responseBody = responseBody.replaceAll("(?:\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01])T(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\dZ)|(?:[A-Za-z]{3},\\s(?:0[1-9]|[12]\\d|3[01])\\s[A-Za-z]{3}\\s\\d{4}\\s(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d\\s[A-Za-z]{3})","0");
			// replace surrounded numbers or versions which might be dynamic
			responseBody = responseBody.replaceAll("\\b[\\d]{1,}?[\\d\\.]*\\b","0");
			// replace Cr and Lf and Null chars
			responseBody = responseBody.replaceAll("(?im)[\\n\\r\\x00]+"," ");
			// replace repetitive spaces
			responseBody = responseBody.replaceAll("(?im)[ \\t]+"," ");
			// convert the response letters to lowercase
			responseBody = responseBody.toLowerCase();
		}

		// return stripped response
		return responseHeaders + responseBody;
	}
}