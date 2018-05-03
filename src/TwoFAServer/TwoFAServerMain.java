package TwoFAServer;

import TwoFAServerGUI.TwoFAServerFrame;

public class TwoFAServerMain { // NO_UCD (unused code)

	public static void main(String[] args) {

		TwoFAServer server = new TwoFAServer(2222);// portNumber

		new TwoFAServerFrame(server).setVisible(true);

		// create a dispatcher object to listen to the given port number
		TwoFAServerDispatcher dispatcher = new TwoFAServerDispatcher(server.getPortNumber());

		// start listening
		try {
			dispatcher.listen(server);
		} catch (Exception e) {
			System.exit(0);
		}

	}

}
