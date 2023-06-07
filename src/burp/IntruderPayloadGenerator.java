package burp;

import java.util.List;

class IntruderPayloadGenerator implements IIntruderPayloadGenerator {
	private List<String> payloads;
	int payloadIndex;

	public IntruderPayloadGenerator(List<String> payloads) {
		this.payloads = payloads;
	}

	@Override
	public boolean hasMorePayloads() {
		return payloadIndex < payloads.size();
	}

	@Override
	public byte[] getNextPayload(byte[] baseValue) {
		byte[] payload = payloads.get(payloadIndex).getBytes();
		payloadIndex++;
		return payload;
	}

	@Override
	public void reset() {
		payloadIndex = 0;
	}
}