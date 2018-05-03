package TwoFAServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

class TwoFAServerDispatcher {

	private Socket clientSocket = null;
	private ServerSocket serverSocket = null;
	private int portNumber = 2222;

	/**
	 * 
	 * @param portNumber
	 */
	TwoFAServerDispatcher(int portNumber) {
		this.portNumber = portNumber;

	}

	/**************************************************************************
	 * listens to the server port and dispatches threads to serve the requests
	 * 
	 * @throws Exception
	 **************************************************************************/
	void listen(TwoFAServer server) {

		try {
			// Initialization section:
			// Try to open a server socket on port portNumber (default 2222)
			serverSocket = new ServerSocket(portNumber);
		} catch (IOException ex) {
			return;
		}

		// Create a socket object from the ServerSocket to listen and accept
		// connections.
		// Open input and output streams for this socket will be created in
		// client's thread since every client is served by the server in
		// an individual thread

		while (true) {

			try {
				clientSocket = serverSocket.accept();
			} catch (IOException ex) {
				return;
			}

			new TwoFAServerThread(clientSocket, server).start();
			// System.out.println("new Thread created");
		}

	}

}
