package TwoFANetworkClient;

import TwoFANetworkClientGUI.TwoFANetClientFrame;

public class TwoFANetClientMain {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		

            TwoFANetClient client = new TwoFANetClient();

            TwoFANetClientFrame a = new TwoFANetClientFrame(client);
            a.setVisible(true);

	}

}
