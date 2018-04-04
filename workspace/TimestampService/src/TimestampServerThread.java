import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class TimestampServerThread extends Thread {
	Socket socket;
	String cmd;

	public TimestampServerThread(Socket socket) {
		super();
		this.socket = socket;
	}
	
	private byte[] getSignedTime() {
		//TODO
		String test = "testtest";
		return test.getBytes();
	}
	
	
	public void run() {
		try {
			PrintWriter printWriter = new PrintWriter(socket.getOutputStream(),true);
			BufferedReader bufferedReader =new BufferedReader( new InputStreamReader(socket.getInputStream()));
			System.out.println("user " + bufferedReader.readLine() +"is connected to TimestampServer");
			while(!(cmd = bufferedReader.readLine()).equals('q')) {
				System.out.println("command: "+cmd+" received");
				
				switch(cmd) {
					case "time":
						byte[] signedTime = getSignedTime();
						printWriter.println(signedTime);
						break;
				}
				printWriter.println("Server is ready for new command");
			}
			
		}catch(IOException e) {
			e.printStackTrace();
		}
	}
	
}
