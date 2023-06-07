package burp;

import java.io.PrintWriter;
import javax.swing.JLabel;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;

class Output {
	private IBurpExtenderCallbacks callbacks;
	private PrintWriter stdout;
	private PrintWriter stderr;
	private JLabel statusLabel;
	private JTextPane outputPane;
	private String output;

	public Output(JTextPane outputPanel, JLabel statusLabel, IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.outputPane = outputPanel;
		this.statusLabel = statusLabel;
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);
		output = "";
	}

	public synchronized void print(String outString) {
		output = output + outString + "\n";
		SwingUtilities.invokeLater(() -> {
			outputPane.setText(output);
			outputPane.setCaretPosition(outputPane.getDocument().getLength());
		});
	}

	public synchronized void printStdout(String out) {
		stdout.println(out);
	}

	public synchronized void printStderr(String err) {
		stderr.println(err);
	}

	public void status(String currentStatus) {
		SwingUtilities.invokeLater(() -> {
			statusLabel.setText(currentStatus);
		});
	}

	public void printAlert(String alert) {
		callbacks.issueAlert(alert);
	}

	public void printStackTrace(Exception e) {
		stderr.println("--------------------\nError stack trace:");
		e.printStackTrace(stderr);
		stderr.println("--------------------\n");
	}
}