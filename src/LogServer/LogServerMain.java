package LogServer;

import java.net.*;
import java.util.StringTokenizer;

public class LogServerMain { // NO_UCD (unused code)

	public static void main(String args[]) throws Exception {

		// start the gui
		LogServerFrame gui = new LogServerFrame();
		gui.setVisible(true);

		int bufferLength = 1024;
		int listenPort = 9999;

		DatagramSocket serverSocket = null;

		try {
			serverSocket = new DatagramSocket(listenPort);

			byte[] receiveData = new byte[bufferLength];
			// byte[] sendData; // = new byte[bufferLength];

			StringTokenizer st = null;
			String first_token = null;

			while (true) {
				DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
				serverSocket.receive(receivePacket);
				String sentence = new String(receivePacket.getData(), 0, receivePacket.getLength());

				st = new StringTokenizer(sentence, "*");
				// find the first token
				if (st.hasMoreTokens()) {
					first_token = st.nextToken();

					if (first_token.equals("Client")) {
						// area = gui.clientArea;
						if (st.hasMoreTokens()) {
							gui.client_string += st.nextToken();
							// area.setText(gui.client_string);
							gui.client_string += "\n";
							gui.server_string += "\n";
							gui.net_client_string += "\n";
						}
					} else if (first_token.equals("NetworkClient")) {
						// area = gui.NetClientArea;
						if (st.hasMoreTokens()) {
							gui.net_client_string += st.nextToken();
							// area.setText(gui.client_string);
							gui.client_string += "\n";
							gui.server_string += "\n";
							gui.net_client_string += "\n";
						}
					} else if (first_token.equals("Server")) {
						// area = gui.ServerArea;
						if (st.hasMoreTokens()) {
							gui.server_string += st.nextToken();
							gui.client_string += "\n";
							gui.server_string += "\n";
							gui.net_client_string += "\n";

							// area.setText(gui.client_string);
						}
					} else
						continue;
				}

				// se all text fields
				gui.clientArea.setText(gui.client_string);
				gui.ServerArea.setText(gui.server_string);
				gui.NetClientArea.setText(gui.net_client_string);
			} // end of while
		} finally {
			if (serverSocket != null)
				serverSocket.close();
		}
	} // end of main

} // end of class
