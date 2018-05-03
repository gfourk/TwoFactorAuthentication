package utils;

import java.io.*;
import java.net.*;

/**
 * 
*
 *
 */
public class Log {
	/******************************************************************************
	 * Sends the message at the udp port 9999 on localhost
	 * 
	 * @param msg
	 * @param souce
	 *            1 for 2FAClient, 2 for 2FAServer,3 for 2FANetworkCLient
	 */
	public static void log(String msg, int source) {
		if (source == 1)// client
			msg = "Client" + "*" + msg;
		else if (source == 2)
			msg = "Server" + "*" + msg;
		else if (source == 3)
			msg = "NetworkClient" + "*" + msg;

		try {
			DatagramSocket clientSocket = new DatagramSocket();
			InetAddress IPAddress = InetAddress.getByName("localhost");
			byte[] sendData = msg.getBytes();
			DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, 9999);
			clientSocket.send(sendPacket);
			clientSocket.close();
		} catch (IOException e) {
			return;
		}
	}

}
