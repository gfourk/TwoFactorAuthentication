package TwoFAClient;

import TwoFAClientGUI.TwoFAClientFrame;

public class TwoFAClientMain {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		
//		for(int i = 0; i<10; i++){
//			TwoFAClient  c = new TwoFAClient();
//			c.connect(2222, "localhost");
//	}
            // create a TWoFAClient class instance
            TwoFAClient client = new TwoFAClient();

            TwoFAClientFrame a = new TwoFAClientFrame(client);
            a.setVisible(true);



            


	}

}
