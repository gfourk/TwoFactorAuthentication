package TwoFAServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;


public class TwoFAServerDispatcher {
	
	
    Socket clientSocket = null;
    ServerSocket serverSocket = null;
    int port_number = 2222;
    
    /**
     * 
     * @param port_number
     */
	public TwoFAServerDispatcher(int port_number){
		this.port_number = port_number;
		
	}
	
	/**************************************************************************
	 * listens to the server port and dispatches threads to serve the requests
	 * @throws Exception
	 **************************************************************************/
	public void listen(TwoFAServer server) {
        try {
            // Initialization section:
            // Try to open a server socket on port port_number (default 2222)
            serverSocket = new ServerSocket(port_number);
        } catch (IOException ex) {
            return;
        }


    	
    	// Create a socket object from the ServerSocket to listen and accept 
    	// connections.
    	// Open input and output streams for this socket will be created in 
    	// client's thread since every client is served by the server in
    	// an individual thread
    	
    	while(true){
            try {
                clientSocket = serverSocket.accept();
            } catch (IOException ex) {
               return;
            }
    	    new TwoFAServerThread(clientSocket,server).start();
            //System.out.println("new Thread created");
    	}
	}

}
