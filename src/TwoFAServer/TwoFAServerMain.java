package TwoFAServer;

import TwoFAServerGUI.TwoFAServerFrame;
import java.io.IOException;
import java.net.*;

public class TwoFAServerMain {

    /****************************************************************************/
    /* 								MAIN 										*/ 
    /****************************************************************************/
	public static void main(String[] args) {

            TwoFAServer server = new TwoFAServer();

            server.port_number = 2222;

            new TwoFAServerFrame(server).setVisible(true);

		
		
		// create a dispatcher object to listen to the given port number
		TwoFAServerDispatcher dispatcher = new TwoFAServerDispatcher(server.port_number);

		// start listening
		try{
			dispatcher.listen(server);
		} catch (Exception e){
			System.exit(0);
		}

	}

}
