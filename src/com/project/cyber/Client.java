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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
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

			String encryptedId = sendMD5UserIdToServer(userId);
			if (encryptedId != null) dos.writeUTF(encryptedId);
			String encryptedString = sendMessageUtil();
			if (encryptedString != null) dos.writeUTF(encryptedString);

		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private static String sendMD5UserIdToServer(String userId) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
			byte[] d1 = md.digest(userId.getBytes());
			StringBuilder sb = new StringBuilder();
			for (byte input : d1) sb.append(String.format("%02X", input));
			String s1 = sb.toString();
			System.out.println(sb.toString());
			return encryptMessageUtil(sb.toString().getBytes());
		} catch (NoSuchAlgorithmException e) {
		}
		return null;
	}

	private static String sendMessageUtil() {
		Scanner sc = new Scanner(System.in);
		String encryptedString = null;
		System.out.println("Do you wish to send a message to anyone? [y/n]\n");
		String yesNo = sc.nextLine();
		if (yesNo.equals("y")) {
			System.out.println("Please enter the recipient's user id...\n");
			String recipientId = sc.nextLine();
//				dos.writeUTF(recipientId);)
			System.out.println("Please enter the message you want to send to this recipient securely...\n");
			String message = sc.nextLine();
			encryptedString = encryptMessageUtil(message.getBytes());
		} else if (yesNo.equals("n")) {
			System.out.println("Nothing more to do now, therefore exiting the program...\n\n");
		} else {
			System.err.println("Invalid response provided, please enter either y or n...\n\n");
			sc.close();
			return sendMessageUtil();
		}
		sc.close();
		return encryptedString;
	}

	private static String encryptMessageUtil(byte[] bytes) {
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
			raw = cipher.doFinal(bytes);
			return Base64.getEncoder().encodeToString(raw);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
		}
		return null;
	}

}
