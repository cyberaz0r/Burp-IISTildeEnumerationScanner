package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

class Bruteforcer extends Thread {
	private volatile boolean looped;
	private volatile boolean terminated;
	private enum FileStatus { NO_FILE, FILE_FOUND, MORE_FILES };
	private ThreadPoolExecutor buildThreadPool;
	private ThreadPoolExecutor bruteThreadPool;
	private CopyOnWriteArrayList<String> filesFound;
	private CopyOnWriteArrayList<String> dirsFound;
	private CopyOnWriteArrayList<String> nameScanList;
	private CopyOnWriteArrayList<String> extScanList;
	private Config config;
	private Output output;
	private Requester requester;
	private String requestFormat;
	private String magicFinalPart;
	private List<String> validStatusResponses;
	private HashMap<String, String> invalidStatusResponses;
	private HashMap<String, String> statusPaths;
	private boolean extensionGuessable;
	private boolean questionMarkReliable;

	public Bruteforcer(Config config, Output output, Requester requester, String requestFormat, String magicFinalPart, HashMap<String, String> statusPaths) {
		buildThreadPool = new ThreadPoolExecutor(config.getNThreads(), config.getNThreads(), 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<Runnable>());
		bruteThreadPool = new ThreadPoolExecutor(config.getNThreads(), config.getNThreads(), 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<Runnable>());
		filesFound = new CopyOnWriteArrayList<String>();
		dirsFound = new CopyOnWriteArrayList<String>();
		nameScanList = new CopyOnWriteArrayList<String>();
		extScanList = new CopyOnWriteArrayList<String>();
		validStatusResponses = new ArrayList<String>();
		invalidStatusResponses = new HashMap<String, String>();
		this.config = config;
		this.output = output;
		this.requester = requester;
		this.requestFormat = requestFormat;
		this.magicFinalPart = magicFinalPart;
		this.statusPaths = statusPaths;
		terminated = false;
		looped = false;
	}

	public List<String> getFilesFound() {
		return filesFound;
	}

	public List<String> getDirsFound() {
		return dirsFound;
	}

	@Override
	public void interrupt() {
		if (terminated)
			return;

		// set termination flag
		terminated = true;

		// reset output to avoid spam printing due to interruption
		output = null;

		// shutdown thread pools before interrupting thread
		buildThreadPool.shutdownNow();
		bruteThreadPool.shutdownNow();

		// wait for their graceful termination before interrupting completely
		try {
			buildThreadPool.awaitTermination(300, TimeUnit.SECONDS);
			bruteThreadPool.awaitTermination(300, TimeUnit.SECONDS);
		}
		catch (InterruptedException e) {
			output.printStackTrace(e);
		}

		// interrupt thread
		super.interrupt();
	}

	@Override
	public void run() {
		// collecting 3 regex-stripped valid status responses for bruteforcing
		for (int i = 0; i < 3; i++) {
			// if the thread is interrupted, do not store the responses and return
			if (terminated)
				return;

			String validStatusResponse = Utils.stripResponse(requester.httpRequest(requestFormat.replace("§PATH§",requester.getBasePath()+Utils.urlEncode(statusPaths.get("validName"))+requester.getQueryString())), statusPaths.get("validName"), requester.getQueryString(), config.getStripLevel());
			if (validStatusResponses.isEmpty() || validStatusResponses.stream().anyMatch(str -> new ResponseDifference(str, validStatusResponse).getDifferences().length() >= config.getDeltaResponseLength())) {
				validStatusResponses.add(validStatusResponse);
			}
		}

		// collecting all regex-stripped invalid status responses for bruteforcing
		for (Map.Entry<String, String> statusPath : statusPaths.entrySet()) {
			if (terminated)
				return;
			if (!statusPath.getKey().startsWith("valid")) {
				String invalidStatusResponse = Utils.stripResponse(requester.httpRequest(requestFormat.replace("§PATH§",requester.getBasePath()+Utils.urlEncode(statusPath.getValue())+requester.getQueryString())), statusPath.getValue(), requester.getQueryString(), config.getStripLevel());
				invalidStatusResponses.put(statusPath.getKey(), invalidStatusResponse);
			}
		}

		// checking if the extension is guessable and if the question mark symbol is reliable
		extensionGuessable = new ResponseDifference(invalidStatusResponses.get("invalidDifferentName"), invalidStatusResponses.get("invalidNameExtension")).getDifferences().length() <= config.getDeltaResponseLength();
		questionMarkReliable = isQuestionMarkReliable();

		// send list building tasks to thread pool
		for (String name : config.getScanList()) {
			buildThreadPool.execute(buildFileNameList(name));
		}
		if (extensionGuessable && config.getExtStartsWith().length() < 3) {
			for (String ext : config.getScanList()) {
				buildThreadPool.execute(buildFileExtList(ext));
			}
		}

		// wait for threadpool to finish list building tasks
		while (buildThreadPool.getActiveCount() > 0 || buildThreadPool.getQueue().size() > 0) {
			try {
				Thread.sleep(500);
			}
			catch (InterruptedException e) {
				return;
			}
		}

		// start brute forcing
		bruteThreadPool.execute(bruteFileName(""));

		// wait for threadpool to finish bruteforcing tasks
		while (bruteThreadPool.getActiveCount() > 0 || bruteThreadPool.getQueue().size() > 0) {
			try {
				Thread.sleep(500);
			}
			catch (InterruptedException e) {
				return;
			}
		}
	}

	private boolean getStatus(String path) {
		return getStatus(path, false);
	}

	private boolean getStatus(String path, boolean retry) {
		String statusResponse = Utils.stripResponse(requester.httpRequest(requestFormat.replace("§PATH§",requester.getBasePath()+Utils.urlEncode(path)+requester.getQueryString())), path, requester.getQueryString(), config.getStripLevel());
		// check if status is a registered invalid
		if (invalidStatusResponses.values().stream().anyMatch(str -> new ResponseDifference(str, statusResponse).getDifferences().length() <= config.getDeltaResponseLength()))
			return false;
		// check if status is a registered valid
		else if (validStatusResponses.stream().anyMatch(str -> new ResponseDifference(str, statusResponse).getDifferences().length() <= config.getDeltaResponseLength()))
			return true;
		// if not, try again with a new request
		else if (!retry)
			return getStatus(path, true);
		// if still not, assume it is valid
		return true;
	}

	private boolean isQuestionMarkReliable() {
		// try match with user-defined question mark symbol first
		if (getStatus(config.getQuestionMarkSymbol()+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+magicFinalPart))
			return true;

		// if failed, try with "?" character
		if (getStatus("?"+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+magicFinalPart)) {
			config.setQuestionMarkSymbol("?");
			return true;
		}

		// if failed, try with ">" character
		if (getStatus(">"+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+magicFinalPart)) {
			config.setQuestionMarkSymbol(">");
			return true;
		}

		// question mark not reliable
		return false;
	}

	private Runnable buildFileNameList(String charScan) {
		return new Runnable() {
			@Override
			public void run() {
				if (terminated)
					return;

				boolean status;

				// when extension should start with something
				if (!config.getExtStartsWith().equals(""))
					status = getStatus(config.getNameStartsWith()+config.getAsteriskSymbol()+charScan+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol() +"."+config.getExtStartsWith()+config.getMagicFileExt()+magicFinalPart);
				else
					status = getStatus(config.getNameStartsWith()+config.getAsteriskSymbol()+charScan+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+magicFinalPart);

				if (status) {
					// it is obviously invalid, but some URL rewriters are sensitive against some characters!
					status = getStatus(config.getNameStartsWith()+config.getAsteriskSymbol()+new String(new char[7]).replace("\0", charScan)+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+"."+config.getExtStartsWith()+config.getMagicFileExt()+magicFinalPart);

					// so if it appears to be valid then something is very wrong!
					if (!status) {
						if (config.getMagicFileExt().equals(""))
							status = getStatus("1234567890"+charScan+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+magicFinalPart);
						else
							status = getStatus("1234567890"+charScan+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+"."+config.getMagicFileExt()+magicFinalPart);

						if (!status) {
							// valid character! adding it to list
							nameScanList.add(charScan);
						}
					}
				}
			}
		};
	}

	private Runnable buildFileExtList(String charScan) {
		return new Runnable() {
			@Override
			public void run() {
				if (terminated)
					return;

				boolean status = getStatus(config.getNameStartsWith()+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+charScan+config.getAsteriskSymbol()+magicFinalPart);

				// should be valid
				if (status) {
					status = getStatus(config.getNameStartsWith()+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+new String(new char[4]).replace("\0", charScan)+config.getAsteriskSymbol()+magicFinalPart);

					// should be invalid
					if (!status) {
						status = getStatus(config.getNameStartsWith()+config.getAsteriskSymbol()+"~1."+config.getAsteriskSymbol()+charScan+"1234567890"+magicFinalPart);

						// if it is invalid, then it is a valid character!
						if (!status)
							extScanList.add(charScan);
					}
				}
			}
		};
	}

	private Runnable bruteFileName(String strFinalInput) {
		return new Runnable() {
			@Override
			public void run() {
				if (terminated)
					return;

				// initialize vars
				String strInput = (strFinalInput.equals("") && !config.getNameStartsWith().equals("")) ? config.getNameStartsWith() : strFinalInput;
				boolean atLeastOneSuccess = false;
				boolean blankChar = false;

				// if due to user-defined name prefix name scan list is empty, add a blank character to it for first iteration
				if (config.getNameStartsWith().length()>0 && !looped && nameScanList.isEmpty()) {
					nameScanList.add("");
					blankChar = true;
					looped = true;
				}

				for (int i = 0; i < nameScanList.size() && !terminated; i++) {
					boolean status;
					String newStr = strInput + nameScanList.get(i).toUpperCase();

					// avoid infinite loop
					if (!looped) {
						looped = true;
						// check if user-defined name prefix appears to be the actual name before appending characters to it
						if (config.getNameStartsWith().length()>0 && isLastFileName(strInput).ordinal()>FileStatus.NO_FILE.ordinal()) {
							blankChar = true;
							newStr = strInput;
							i--;
						}
					}

					// if extension should start with something
					if (!config.getExtStartsWith().equals(""))
						status = getStatus(newStr+config.getMagicFileName()+"."+config.getExtStartsWith()+config.getMagicFileExt()+magicFinalPart);
					else
						status = getStatus(newStr+config.getMagicFileName()+magicFinalPart);

					// showing progress in status
					output.status("Scanning " + newStr);

					if (status) {
						atLeastOneSuccess = true;
						FileStatus isItLastFileName = isLastFileName(newStr);

						if (isItLastFileName.ordinal() > FileStatus.NO_FILE.ordinal()) {
							int counter = 1;

							// loop numerical part
							while ((status && counter <= config.getMaxNumericalPart()) || (counter <= config.getForceNumericalPart() && counter > 1)) {
								String fileName = newStr + "~" + counter;

								// folder
								if (isFolder(fileName)) {
									output.print("[i] Dir: " + fileName.toUpperCase());
									dirsFound.add(fileName.toUpperCase());
								}

								// file with extension
								if (extensionGuessable) {
									fileName += ".";

									// if user-defined extension prefix is the actual extension, try guessing first without adding characters
									if (config.getExtStartsWith().length() > 0) {
										output.status("Scanning " + fileName + config.getExtStartsWith().toUpperCase());

										if (isLastFileExt(fileName+config.getExtStartsWith())) {
											fileName += config.getExtStartsWith().toUpperCase();
											output.print("[i] File: " + fileName.toUpperCase());
											filesFound.add(fileName.toUpperCase());
										}

										// do not guess if user-defined extension prefix is already 3 characters long
										else if (config.getExtStartsWith().length() < 3) {
											bruteThreadPool.execute(bruteFileExt(fileName, ""));
										}
									}

									// guessing file extension before adding it to results
									else {
										bruteThreadPool.execute(bruteFileExt(fileName, ""));
									}

									// if extension should start with something, append it before iterating numerical part to avoid false positives
									if (config.getExtStartsWith().length() > 0)
										status = getStatus(newStr+config.getMagicFileName().replace("1",Integer.toString(++counter))+"."+config.getExtStartsWith()+magicFinalPart);
									else
										status = getStatus(newStr+config.getMagicFileName().replace("1",Integer.toString(++counter))+magicFinalPart);
								}
								else {
									// extension not guessable, adding file to results with "???" extension
									output.print("[i] File: " + fileName.toUpperCase() + ".??? - extension cannot be found");
									filesFound.add(fileName.toUpperCase()+".???");
									status = false;
								}
							}

							// more files with the same name
							if (isItLastFileName == FileStatus.MORE_FILES) {
								// avoid infinite loop that iterates blank character over and over again
								if (!blankChar || !(config.getNameStartsWith().length()>0 && config.getExtStartsWith().length()>0))
									bruteThreadPool.execute(bruteFileName(newStr));
							}
							 
						}
						else {
							// if the iterated character is not blank: filename not finished, passing to next character
							if (!blankChar)
								bruteThreadPool.execute(bruteFileName(newStr));
						}
					}
					else {
						// unfinished string
						if (strInput.length()>0 && strInput.equals(config.getNameStartsWith()) && !atLeastOneSuccess && i==(nameScanList.size()-1) && !blankChar) {
							// we have a failure here... it should have at least found 1 item!
							String unFinishedString = String.format("%1s%2$" + (6 - strInput.length()) + "s~?", strInput.toUpperCase(), "?????");
							output.print("[i] File/Dir: " + unFinishedString + " - possible network/server problem");
							dirsFound.add(unFinishedString);
						}
					}
				}
			}
		};
	}

	private Runnable bruteFileExt(String strFilename, String strFinalInput) {
		return new Runnable() {
			@Override
			public void run() {
				if (terminated)
					return;

				String strInput = (strFinalInput.equals("") && !config.getExtStartsWith().equals("")) ? config.getExtStartsWith() : strFinalInput;
				boolean atLeastOneSuccess = false;

				for (int i = 0; i < extScanList.size() && !terminated; i++) {
					boolean status;
					String newStr = strInput + extScanList.get(i).toUpperCase();

					if (newStr.length() <= 2)
						status = getStatus(strFilename+newStr+config.getMagicFileExt()+magicFinalPart);
					else
						status = getStatus(strFilename+newStr+magicFinalPart);

					// showing progress in status
					output.status("Scanning " + strFilename + newStr);

					if (status) {
						atLeastOneSuccess = true;

						if (isLastFileExt(strFilename + newStr)) {
							// adding it to final list
							String fileName = strFilename + newStr;

							output.print("[i] File: " + fileName.toUpperCase());
							filesFound.add(fileName.toUpperCase());
						}
						else {
							bruteThreadPool.execute(bruteFileExt(strFilename, newStr));
						}
					}
					else {
						// unfinished string
						if (strInput.length()>0 && !atLeastOneSuccess && i==(extScanList.size()-1)) {
							// we have a failure here... it should have at least found 1 item!
							String unFinishedString = strFilename + String.format("%1s%2$" + (3 - strInput.length()) + "s", strInput.toUpperCase(), "??");
							output.print("[i] File: " + unFinishedString + " - possible network/server problem");
							filesFound.add(unFinishedString);
						}
					}
				}
			}
		};
	}

	private FileStatus isLastFileName(String strInput) {
		// valid file, but there are no more files with the same name
		FileStatus result = FileStatus.FILE_FOUND;

		if (!questionMarkReliable) {
			// can't use "?" for this validation, this result will include false positives...
			result = FileStatus.MORE_FILES;
		}

		else {
			if (strInput.length() < 6) {
				boolean status = getStatus(strInput+config.getQuestionMarkSymbol()+config.getAsteriskSymbol()+"~1"+config.getAsteriskSymbol()+magicFinalPart);

				if (status) {
					// file not completed
					result = FileStatus.NO_FILE;

					status = getStatus(strInput+"~1"+config.getAsteriskSymbol()+magicFinalPart);

					if (status) {
						// valid file, but there are more as well with the same name
						result = FileStatus.MORE_FILES;
					}

				}
				else {
					// sometimes in rare cases we can see that a virtual directory is still there with more character
					status = getStatus(strInput+"~1"+config.getAsteriskSymbol()+magicFinalPart);

					if (!status) {
						// file is not completed
						result = FileStatus.NO_FILE;
					}
				}
			}
		}

		return result;
	}

	private boolean isLastFileExt(String strInput) {
		// extension not guessable, so it has to be the last character
		if (!extensionGuessable)
			return true;

		// max length not reached
		if (strInput.length() <= 12) {
			// default extension length
			int extLength = 3;

			// check last extension character
			if (strInput.indexOf(".")>0 && strInput.indexOf(".")!=(strInput.length()-1)) {
				if (strInput.split("\\.")[1].length() >= extLength || getStatus(strInput+"."+config.getAsteriskSymbol()+magicFinalPart)) {
					return true;
				}
			}

			// if it is not the last character, it has to be invalid
			if (!getStatus(strInput+config.getMagicFileExt()+magicFinalPart))
				return true;
		}

		// extension is not finished
		return false;
	}

	private boolean isFolder(String strInput) {
		// can't use "?" for validation, too many false positives here...
		if (!questionMarkReliable)
			return true;

		if (getStatus(strInput+config.getQuestionMarkSymbol()+magicFinalPart)) {
			String statusResponseQuestion = Utils.stripResponse(requester.httpRequest(requestFormat.replace("§PATH§",requester.getBasePath()+Utils.urlEncode(strInput+config.getQuestionMarkSymbol()+magicFinalPart)+requester.getQueryString())), strInput+config.getQuestionMarkSymbol()+magicFinalPart, requester.getQueryString(), config.getStripLevel());
			String statusResponseAsterisk = Utils.stripResponse(requester.httpRequest(requestFormat.replace("§PATH§",requester.getBasePath()+Utils.urlEncode(strInput+config.getAsteriskSymbol()+magicFinalPart)+requester.getQueryString())), strInput+config.getAsteriskSymbol()+magicFinalPart, requester.getQueryString(), config.getStripLevel());
			if (new ResponseDifference(statusResponseQuestion, statusResponseAsterisk).getDifferences().length() <= config.getDeltaResponseLength()) {
				// a directory
				return true;
			}
		}

		// no dir or file
		return false;
	}
}