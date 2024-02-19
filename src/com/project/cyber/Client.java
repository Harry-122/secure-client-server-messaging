package com.project.cyber;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client {

	public static void main(String[] args) {

		if (args.length != 3) {
			System.out.println("The length of the provided arguments is incorrect!!!");
			System.out.println(
					"Please provide correct arguments that are space-seperated values denoting host, port and userid...");
			return;
		}

		String host = args[0];
		Integer port = Integer.parseInt(args[1]);
		String userId = args[2];

		System.out.println("Hello " + userId);

		try (Socket s = new Socket(host, port);
				DataOutputStream dos = new DataOutputStream(s.getOutputStream());
				DataInputStream dis = new DataInputStream(s.getInputStream());) {

			dos.writeUTF("Hello World!");
			System.out.println(dis.readUTF());
			dos.writeUTF("Happy new year!");
			System.out.println(dis.readUTF());
			dos.writeUTF("Hello World2!");
			System.out.println(dis.readUTF());
			dos.writeUTF("Happy new year2!");
			System.out.println(dis.readUTF());

		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
