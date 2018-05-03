package be.msec.helpers;

public class StoppableThread extends Thread {
    public volatile boolean running = true;

    public void requestStop() {
        running = false;
    }
}
