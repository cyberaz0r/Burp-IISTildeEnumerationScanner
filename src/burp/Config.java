package burp;

import java.util.List;
import java.util.Arrays;
import java.util.HashMap;
import java.io.File;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JCheckBox;

class Config {
	private List<String> magicFinalPartList;
	private List<String> requestMethods;
	private List<String> scanList;
	private String requestString;
	private String questionMarkSymbol;
	private String asteriskSymbol;
	private String magicFileName;
	private String magicFileExt;
	private String urlSuffix;
	private String nameStartsWith;
	private String extStartsWith;
	private int maxNumericalPart;
	private int forceNumericalPart;
	private int deltaResponseLength;
	private int stripLevel;
	private int delay;
	private int nThreads;
	private boolean exploitMode;
	private boolean completeFileGuessSitemap;
	private boolean completeFileGuessWordlist;
	private File fileNameWordlist;
	private File fileExtWordlist;

	public Config(HashMap<String, JTextField> confFields, JTextPane requestEditor, JTextField nThreadsField, JCheckBox exploitModeCheckbox, JCheckBox completeFileGuessSitemapCheckbox, JCheckBox completeFileGuessWordlistCheckbox) {
		this.magicFinalPartList = Arrays.asList(confFields.get("magicFinalPartList").getText().split(","));
		this.questionMarkSymbol = confFields.get("questionMarkSymbol").getText();
		this.asteriskSymbol = confFields.get("asteriskSymbol").getText();
		this.magicFileName = confFields.get("magicFileName").getText();
		this.magicFileExt = confFields.get("magicFileExt").getText();
		this.urlSuffix = confFields.get("urlSuffix").getText();
		this.requestMethods = Arrays.asList(confFields.get("requestMethods").getText().split(","));
		this.nameStartsWith = confFields.get("nameStartsWith").getText().toUpperCase();
		this.extStartsWith = confFields.get("extStartsWith").getText().toUpperCase();
		this.maxNumericalPart = Integer.parseInt(confFields.get("maxNumericalPart").getText());
		this.forceNumericalPart = Integer.parseInt(confFields.get("forceNumericalPart").getText());
		this.deltaResponseLength = Integer.parseInt(confFields.get("deltaResponseLength").getText());
		this.stripLevel = Integer.parseInt(confFields.get("stripLevel").getText());
		this.delay = Integer.parseInt(confFields.get("delay").getText());
		this.scanList = Arrays.asList(confFields.get("inScopeCharacters").getText().split(""));
		this.requestString = requestEditor.getText();
		this.nThreads = Integer.parseInt(nThreadsField.getText());
		this.exploitMode = exploitModeCheckbox.isSelected();
		this.completeFileGuessSitemap = completeFileGuessSitemapCheckbox.isSelected();
		this.completeFileGuessWordlist = completeFileGuessWordlistCheckbox.isSelected();
		this.fileNameWordlist = new File(confFields.get("fileNameWordlist").getText());
		this.fileExtWordlist = new File(confFields.get("fileExtWordlist").getText());
	}

	public List<String> getMagicFinalPartList() {
		return magicFinalPartList;
	}

	public List<String> getRequestMethods() {
		return requestMethods;
	}

	public List<String> getScanList() {
		return scanList;
	}

	public String getRequestString() {
		return requestString;
	}

	public String getQuestionMarkSymbol() {
		return questionMarkSymbol;
	}

	public String getAsteriskSymbol() {
		return asteriskSymbol;
	}

	public String getMagicFileName() {
		return magicFileName;
	}

	public String getMagicFileExt() {
		return magicFileExt;
	}

	public String getUrlSuffix() {
		return urlSuffix;
	}

	public String getNameStartsWith() {
		return nameStartsWith;
	}

	public String getExtStartsWith() {
		return extStartsWith;
	}

	public int getMaxNumericalPart() {
		return maxNumericalPart;
	}

	public int getForceNumericalPart() {
		return forceNumericalPart;
	}

	public int getDeltaResponseLength() {
		return deltaResponseLength;
	}

	public int getStripLevel() {
		return stripLevel;
	}

	public int getDelay() {
		return delay;
	}

	public int getNThreads() {
		return nThreads;
	}

	public boolean getExploitMode() {
		return exploitMode;
	}

	public boolean getCompleteFileGuessSitemap() {
		return completeFileGuessSitemap;
	}

	public boolean getCompleteFileGuessWordlist() {
		return completeFileGuessWordlist;
	}

	public File getFileNameWordlist() {
		return fileNameWordlist;
	}

	public File getFileExtWordlist() {
		return fileExtWordlist;
	}

	public void setQuestionMarkSymbol(String questionMarkSymbol) {
		this.questionMarkSymbol = questionMarkSymbol;
	}
}