package burp;

import java.io.PrintWriter;
import java.util.HashMap;
import java.awt.Font;
import java.awt.Color;
import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.Timer;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JScrollPane;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JCheckBox;
import javax.swing.BoxLayout;
import javax.swing.SwingUtilities;
import javax.swing.SwingConstants;
import javax.swing.BorderFactory;
import javax.swing.border.EmptyBorder;
import javax.swing.border.CompoundBorder;

public class BurpExtender implements IBurpExtender, ITab {
	private final String NAME = "IIS Tilde Enumeration Scanner";
	private final String VERSION = "2.0";
	private final String AUTHOR = "Michele 'cyberaz0r' Di Bonaventura";

	private JTabbedPane mainUI;
	private JButton scanButton;

	private TildeEnumerationScanner tildeEnumerationScanner;

	// extension tab name
	@Override
	public String getTabCaption() {
		return "IIS Tilde Enumeration";
	}

	// main UI panel
	@Override
	public Component getUiComponent() {
		return mainUI;
	}

	// UI setup
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		// print extension info on loading
		PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
		stdout.println(NAME + " v" + VERSION + "\nBy " + AUTHOR);

		// extension name
		callbacks.setExtensionName(NAME);

		// register scanner checks
		callbacks.registerScannerCheck(new ScannerCheck(callbacks));

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// setting up UI divided in 2 tabs: scanner and configuration
				mainUI = new JTabbedPane();

				// setting up configuration tab divided in 2 panels: request panel and configuration panel
				JSplitPane configTab = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
				configTab.setBorder(new EmptyBorder(20, 20, 20, 20));

				// setting up listener for splitting the configuration tab pane 50:50
				ActionListener splitListener = new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						configTab.setDividerLocation(.5);
					}
				};
				Timer t = new Timer(500, splitListener);
				t.setRepeats(false);

				// setting up config panel in configuration tab
				JPanel rightPanel = new JPanel();
				rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
				JScrollPane rightScrollPanel = new JScrollPane(rightPanel);
				rightScrollPanel.setBorder(new EmptyBorder(20, 20, 20, 20));

				JPanel confPanel = new JPanel(new GridLayout(31, 1));

				JLabel confTitle = new JLabel("Configuration");
				confTitle.setForeground(new Color(249, 130, 11));
				confTitle.setFont(new Font("Nimbus", Font.BOLD, 16));
				confTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
				confTitle.setBorder(new CompoundBorder(confTitle.getBorder(), new EmptyBorder(10, 10, 10, 10)));
				confPanel.add(confTitle);

				// setting up request panel in configuration tab
				JPanel requestPanel = new JPanel();
				requestPanel.setLayout(new BoxLayout(requestPanel, BoxLayout.Y_AXIS));
				requestPanel.setBorder(new EmptyBorder(20, 20, 20, 20));

				JLabel requestTitle = new JLabel("Request Editor");
				requestTitle.setForeground(new Color(249, 130, 11));
				requestTitle.setFont(new Font("Nimbus", Font.BOLD, 16));
				requestTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
				requestTitle.setBorder(new CompoundBorder(requestTitle.getBorder(), new EmptyBorder(10, 10, 10, 10)));

				// setting up elements in request panel in configuration tab
				JTextPane requestEditor = new JTextPane();
				JScrollPane requestScrollEditor = new JScrollPane(requestEditor);
				requestEditor.setFont(new Font("Courier", 0, 14));
				requestEditor.setBorder(BorderFactory.createLineBorder(Color.BLACK));
				requestEditor.setText(
					"§METHOD§ §PATH§ HTTP/1.1\n" +
					"Host: §HOST§\n" +
					"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36\n" +
				"\n");

				requestPanel.add(requestTitle);
				requestPanel.add(requestScrollEditor);

				// setting up elements in config panel in configuration tab
				HashMap<String, JTextField> confFields = new HashMap<String, JTextField>();

				confPanel.add(new JLabel("Magic Final Part List (separated by comma):"));
				confFields.put("magicFinalPartList", new JTextField("/~1/.rem,/~1/,\\a.aspx,\\a.asp,/a.aspx,/a.asp,/a.shtml,/a.asmx,/a.ashx,/a.config,/a.php,/a.jpg,/webresource.axd,/a.xxx", 50));
				confPanel.add(confFields.get("magicFinalPartList"));

				confPanel.add(new JLabel("Question Mark Symbol:"));
				confFields.put("questionMarkSymbol", new JTextField("?", 50));
				confPanel.add(confFields.get("questionMarkSymbol"));

				confPanel.add(new JLabel("Asterisk Symbol:"));
				confFields.put("asteriskSymbol", new JTextField("*", 50));
				confPanel.add(confFields.get("asteriskSymbol"));

				confPanel.add(new JLabel("Magic File Name:"));
				confFields.put("magicFileName", new JTextField("*~1*", 50));
				confPanel.add(confFields.get("magicFileName"));

				confPanel.add(new JLabel("Magic File Extension:"));
				confFields.put("magicFileExt", new JTextField("*", 50));
				confPanel.add(confFields.get("magicFileExt"));

				confPanel.add(new JLabel("URL Suffix for error display:"));
				confFields.put("urlSuffix", new JTextField("?&aspxerrorpath=/", 50));
				confPanel.add(confFields.get("urlSuffix"));

				confPanel.add(new JLabel("Request methods (separated by comma):"));
				confFields.put("requestMethods", new JTextField("OPTIONS,POST,DEBUG,TRACE,GET,HEAD", 50));
				confPanel.add(confFields.get("requestMethods"));

				confPanel.add(new JLabel("File Name starts with:"));
				confFields.put("nameStartsWith", new JTextField("", 50));
				confPanel.add(confFields.get("nameStartsWith"));

				confPanel.add(new JLabel("File Extension starts with:"));
				confFields.put("extStartsWith", new JTextField("", 50));
				confPanel.add(confFields.get("extStartsWith"));

				confPanel.add(new JLabel("Max Numerical Part:"));
				confFields.put("maxNumericalPart", new JTextField("4", 50));
				confPanel.add(confFields.get("maxNumericalPart"));

				confPanel.add(new JLabel("Force Numerical Part:"));
				confFields.put("forceNumericalPart", new JTextField("1", 50));
				confPanel.add(confFields.get("forceNumericalPart"));

				confPanel.add(new JLabel("Dynamic content strip level (for more regexes, higher levels may cause false negatives):"));
				confFields.put("stripLevel", new JTextField("1", 50));
				confPanel.add(confFields.get("stripLevel"));

				confPanel.add(new JLabel("Delay between requests (in milliseconds):"));
				confFields.put("delay", new JTextField("0", 50));
				confPanel.add(confFields.get("delay"));

				confPanel.add(new JLabel("Delta Value for response difference:"));
				confFields.put("deltaResponseLength", new JTextField("75", 50));
				confPanel.add(confFields.get("deltaResponseLength"));

				confPanel.add(new JLabel("In-Scope characters:"));
				confFields.put("inScopeCharacters", new JTextField("ETAONRISHDLFCMUGYPWBVKJXQZ0123456789_-$~()&!#%'@^`{}", 50));
				confPanel.add(confFields.get("inScopeCharacters"));

				JPanel filenameGuessingPanel = new JPanel(new GridLayout(3, 1));
				JPanel filenameGuessingFields = new JPanel(new GridLayout(4, 1));

				JLabel filenameGuessingTitle = new JLabel("Complete filename guessing");
				filenameGuessingTitle.setForeground(new Color(249, 130, 11));
				filenameGuessingTitle.setFont(new Font("Nimbus", Font.BOLD, 16));
				filenameGuessingTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
				filenameGuessingTitle.setBorder(new CompoundBorder(confTitle.getBorder(), new EmptyBorder(10, 10, 10, 10)));
				filenameGuessingPanel.add(filenameGuessingTitle);

				JCheckBox completeFileGuessSitemapCheckbox = new JCheckBox("Use Burp sitemap words to create an Intruder Payload Set with possible filenames", false);
				JCheckBox completeFileGuessWordlistCheckbox = new JCheckBox("Use wordlists to create an Intruder Payload Set with possible filenames\n (might consume resources and impact performance if large wordlists are used)", false);
				filenameGuessingPanel.add(completeFileGuessSitemapCheckbox);
				filenameGuessingPanel.add(completeFileGuessWordlistCheckbox);

				filenameGuessingFields.add(new JLabel("Complete file name wordlist:"));
				confFields.put("fileNameWordlist", new JTextField("", 50));
				filenameGuessingFields.add(confFields.get("fileNameWordlist"));

				filenameGuessingFields.add(new JLabel("Complete file extension wordlist:"));
				confFields.put("fileExtWordlist", new JTextField("", 50));
				filenameGuessingFields.add(confFields.get("fileExtWordlist"));

				rightPanel.add(confPanel);
				rightPanel.add(filenameGuessingPanel);
				rightPanel.add(filenameGuessingFields);

				// setting up scanner tab
				JSplitPane scannerTab = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
				scannerTab.setBorder(new EmptyBorder(20, 20, 20, 20));

				JPanel scannerTopPanel = new JPanel(new GridLayout(2, 1));
				scannerTopPanel.setBorder(new EmptyBorder(0, 0, 10, 0));

				JPanel scannerBottomPanel = new JPanel(new BorderLayout(10, 10));
				scannerBottomPanel.setBorder(new EmptyBorder(0, 0, 10, 0));

				// setting up elements in scanner tab
				JTextPane textPane = new JTextPane();
				JScrollPane textScrollPane = new JScrollPane(textPane);
				textPane.setFont(new Font("Courier", 0, 12));
				textPane.setText("IIS Tilde Enumeration Scanner Burp Extension is ready\nThe scan output will be displayed here");
				textPane.setEditable(false);

				JPanel moreOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 10, 10));

				JCheckBox exploitModeCheckbox = new JCheckBox("Exploit the vulnerability (opt out for only checking)", true);
				moreOptionsPanel.add(exploitModeCheckbox, BorderLayout.LINE_START);

				JButton saveOutputButton = new JButton("Save output to file");
				moreOptionsPanel.add(saveOutputButton);

				moreOptionsPanel.add(new JLabel("          Status: ", SwingConstants.LEFT), BorderLayout.CENTER);
				JLabel statusLabel = new JLabel("Ready to scan", SwingConstants.LEFT);
				moreOptionsPanel.add(statusLabel);

				JPanel barPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 10, 10));

				barPanel.add(new JLabel("Target URL:", SwingConstants.LEFT), BorderLayout.LINE_START);
				JTextField targetUrlField = new JTextField("", 50);
				barPanel.add(targetUrlField);

				barPanel.add(new JLabel("Number of threads:", SwingConstants.LEFT), BorderLayout.CENTER);
				JTextField nThreadsField = new JTextField("20", 3);
				barPanel.add(nThreadsField);

				scanButton = new JButton("Scan");
				scanButton.setBackground(new Color(249, 130, 11));
				scanButton.setForeground(Color.WHITE);
				scanButton.setFont(new Font("Nimbus", Font.BOLD, 14));
				barPanel.add(scanButton);

				// setting up action listener for scan button
				scanButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent a) {
						// check if a scan is already running, and stop it in case it is
						if (tildeEnumerationScanner != null && tildeEnumerationScanner.isAlive()) {
							tildeEnumerationScanner.interrupt();
						}
						else if (checkValidFieldValues(nThreadsField, confFields, textPane)) {
							tildeEnumerationScanner = new TildeEnumerationScanner(targetUrlField.getText(), new Config(confFields, requestEditor, nThreadsField, exploitModeCheckbox, completeFileGuessSitemapCheckbox, completeFileGuessWordlistCheckbox), new Output(textPane, statusLabel, callbacks), scanButton, callbacks);
							tildeEnumerationScanner.start();
						}
					}
				});

				// setting up action listener for save output button
				saveOutputButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent a) {
						Utils.saveOutputToFile(callbacks, textPane, targetUrlField);
					}
				});

				// building UI
				scannerTopPanel.add(barPanel);
				scannerTopPanel.add(moreOptionsPanel);
				scannerBottomPanel.add(textScrollPane, BorderLayout.CENTER);

				scannerTab.setTopComponent(scannerTopPanel);
				scannerTab.setBottomComponent(scannerBottomPanel);

				configTab.setTopComponent(requestPanel);
				configTab.setBottomComponent(rightScrollPanel);

				t.start(); // triggering listener for splitting config tab 50:50

				callbacks.customizeUiComponent(scannerTab);
				callbacks.customizeUiComponent(configTab);

				mainUI.addTab("Scanner", scannerTab);
				mainUI.addTab("Configuration", configTab);

				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	// check if all field values are valid before sending them to the scanner thread
	private boolean checkValidFieldValues(JTextField nThreadsField, HashMap<String, JTextField> confFields, JTextPane textPane) {
		// handle invalid value for thread numbers
		try {
			Integer.parseInt(nThreadsField.getText());
		}
		catch (Exception e) {
			textPane.setText("[X] Error: number of thread should be an integer value");
			return false;
		}

		// handle invalid value for delta response length
		try {
			Integer.parseInt(confFields.get("deltaResponseLength").getText());
		}
		catch (Exception e) {
			textPane.setText("[X] Error: delta response difference should be an integer value (indicating the maximum acceptable response difference in bytes)");
			return false;
		}

		// handle invalid value for strip level
		try {
			Integer.parseInt(confFields.get("stripLevel").getText());
		}
		catch (Exception e) {
			textPane.setText("[X] Error: dynamic strip level should be an integer value");
			return false;
		}

		// handle invalid value for delay between requests
		try {
			Integer.parseInt(confFields.get("delay").getText());
		}
		catch (Exception e) {
			textPane.setText("[X] Error: delay between requests should be an integer value");
			return false;
		}

		// handle invalid value for max numerical part
		try {
			Integer.parseInt(confFields.get("maxNumericalPart").getText());
		}
		catch (Exception e) {
			textPane.setText("[X] Error: max numerical part should be an integer value (indicating the maximum value of the numerical part of the filename)");
			return false;
		}

		// handle invalid value for force numerical part
		try {
			Integer.parseInt(confFields.get("forceNumericalPart").getText());
		}
		catch (Exception e) {
			textPane.setText("[X] Error: force numerical part should be an integer value (indicating the forced value of the numerical part in bruteforce mode)");
			return false;
		}

		// all valid values, check passed
		return true;
	}
}