package burp;

import org.apache.commons.text.diff.StringsComparator;
import org.apache.commons.text.diff.CommandVisitor;

class ResponseDifference implements CommandVisitor<Character> {
	private String stripped;
	private String difference;

	public ResponseDifference(String response1, String response2) {
		stripped = "";
		difference = "";
		StringsComparator comparator = new StringsComparator(response1, response2);
		comparator.getScript().visit(this);
	}

	public String getDifferences() {
		return difference;
	}

	public String getStripped() {
		return stripped;
	}

	@Override
	public void visitKeepCommand(Character c) {
		stripped += c;
	}

	@Override
	public void visitInsertCommand(Character c) {
		difference += c;
	}

	@Override
	public void visitDeleteCommand(Character c) {
		difference += c;
	}
}