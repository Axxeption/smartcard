package be.msec.helpers;

import java.util.ArrayList;
import java.util.List;

public class Controller {
    public List<StoppableThread> controllerThreads;

    public Controller() {
        this.controllerThreads = new ArrayList<>();
    }

    public void stopAllThreads() {
        System.out.println("STOP CONTROLLER THREADS");
        for (StoppableThread thread : controllerThreads) {
            thread.requestStop();
            thread.interrupt(); // Weet niet zeker hoe een thread die geblokeerd is gestopt kan worden. Dacht door die te interupte maar doet nog niet wat ik wil.
        }
    }
}
