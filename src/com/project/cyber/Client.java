package com.project.cyber;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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

			sendMessageUtil(dos);
			System.out.println(dis.readUTF());

		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private static void sendMessageUtil(DataOutputStream dos) {
		Scanner sc = new Scanner(System.in);
		System.out.println("Do you wish to send a message to anyone? [y/n]\n");
		String yesNo = sc.nextLine();
		if (yesNo.equals("y")) {
			System.out.println("Please enter the recipient's user id...\n");
			String recipientId = sc.nextLine();
//				dos.writeUTF(recipientId);)
			System.out.println("Please enter the message you want to send to this recipient securely...\n");
			String message = sc.nextLine();
			encryptMessageUtil(message, dos);
		} else if (yesNo.equals("n")) {
			System.out.println("Nothing more to do now, therefore exiting the program...\n\n");
		} else {
			System.err.println("Invalid response provided, please enter either y or n...\n\n");
			sendMessageUtil(dos);
		}
		sc.close();
	}

	private static void encryptMessageUtil(String message, DataOutputStream dos) {
		PublicKey pubKey = null;
		try {
			File f = new File("server.pub");
			byte[] keyBytes = Files.readAllBytes(f.toPath());
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			pubKey = kf.generatePublic(pubSpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
		}

		byte[] raw = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			raw = cipher.doFinal(message.getBytes());
			System.out.println(raw);
			dos.writeUTF(Base64.getEncoder().encodeToString(raw));
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
		}

	}

}
