package be.msec.client;

public enum CallableMiddelwareMethodes {
	AUTH_SP(1), GET_DATA(2), VERIFY_CHALLENGE(3), AUTH_CARD(4), IDENTIFICATION(5), AUTH_TO_SP(6), CONFIRM_REQUEST(7), INIT_SIGN(8);
	
	private int command_value;
	private CallableMiddelwareMethodes(int cmd) {
		this.command_value = cmd;
	}
	public int getCommand_value() {
		return command_value;
	}
	public String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", ";
		return str;
	}
	
}
