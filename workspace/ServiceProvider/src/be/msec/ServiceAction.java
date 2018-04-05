package be.msec;
public class ServiceAction {

    String name;
    short command;
    // MSS INTERFACE VAN MAKEN VAN DIE ACTIONS

    public ServiceAction(String name, int command) {
        this.name = name;
        this.command = (short) command;
    }
    
    
    public short getCommand() {
		return command;
	}


	public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
