package be.msec;
public class ServiceAction {

    String name;
    String command;
    // MSS INTERFACE VAN MAKEN VAN DIE ACTIONS

    public ServiceAction(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
