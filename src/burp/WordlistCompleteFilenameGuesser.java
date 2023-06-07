package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Collections;
import java.io.File;

class WordlistCompleteFilenameGuesser extends Thread implements IIntruderPayloadGeneratorFactory {
	private File fileNameWordlist;
	private File fileExtWordlist;
	private List<String> filesFound;
	private List<String> dirsFound;
	private List<String> intruderPayloads;

	public WordlistCompleteFilenameGuesser(List<String> dirsFound, List<String> filesFound, File fileNameWordlist, File fileExtWordlist) {
		this.fileNameWordlist = fileNameWordlist;
		this.fileExtWordlist = fileExtWordlist;
		this.filesFound = filesFound;
		this.dirsFound = dirsFound;
	}

	public List<String> getPayloads() {
		return intruderPayloads;
	}

	@Override
	public String getGeneratorName() {
		return "IISTildeEnumeration - wordlist-based full filename guessing";
	}

	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
		return new IntruderPayloadGenerator(intruderPayloads);
	}

	@Override
	public void run() {
		intruderPayloads = new ArrayList<String>();
		List<String> elementsFound = Utils.buildElementList(dirsFound, filesFound);
		List<String> possibleFileNames = Utils.readWordlist(fileNameWordlist); 
		List<String> possibleFileExts = Utils.readWordlist(fileExtWordlist);

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

		intruderPayloads = new ArrayList<String>(new LinkedHashSet<>(intruderPayloads));
		Collections.sort(intruderPayloads);
	}
}