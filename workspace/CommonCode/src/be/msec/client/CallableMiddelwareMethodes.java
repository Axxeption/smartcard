package be.msec.client;

public enum CallableMiddelwareMethodes {
	AUTH_SP(1), GET_DATA(2);
	
	private int command_value;
	private CallableMiddelwareMethodes(int cmd) {
		this.command_value = cmd;
	}
	public int getCommand_value() {
		return command_value;
	}
	
}
