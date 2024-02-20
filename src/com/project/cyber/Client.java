package com.project.cyber;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.project.cyber.Server.MessageContent;

public class Client {

	private static final String SERVER = "server";
	private static final String PUBLIC_KEY = ".pub";
	private static final String PRIVATE_KEY = ".prv";
	private static final String PREPEND_STRING = "gfhk2024:";
	private static final String HEX_FORMAT = "%02X";
	private static final String MD5 = "MD5";

	private static String host;
	private static Integer port;
	private static String userId;

	public static void main(String[] args) {

		initializeHostPortUserId(args);

		System.out.println("Hello " + userId);

		try (Socket s = new Socket(host, port);
				DataOutputStream dos = new DataOutputStream(s.getOutputStream());
				ObjectInputStream ois = new ObjectInputStream(s.getInputStream());) {

			communicateWithTheServer(ois, dos);

		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private static void communicateWithTheServer(ObjectInputStream ois, DataOutputStream dos) {
		try {
			String hashedId = convertUserIdToHashedMD5Id(userId);
			if (hashedId != null) {
				dos.writeUTF(hashedId);
			}

			receiveUnreadMessages(ois);

			String encryptedString = askUserToSendMessage();
			if (encryptedString != null) {
				dos.writeUTF(encryptedString);
				Long timestamp = new Date().getTime();
				dos.writeLong(timestamp);
				dos.writeUTF(userId);

				byte[] signature = getSignature(encryptedString, timestamp);
				dos.write(signature);

				System.out.println("\nYour message is securely sent to the server...");
				System.out.println("It will be delivered to the recipient when they log in...\n");
				System.out.println("Nothing more to do now, therefore logging out!!!\n\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void receiveUnreadMessages(ObjectInputStream ois) {
		try {
			Integer messageLength = null;
			if ((messageLength = ois.readInt()) != null) {
				System.out.println("There are " + messageLength + " unread message(s) for you...");
				while (messageLength-- > 0) {
					byte[] signature = null;
					MessageContent content = null;
					try {
						if ((content = (MessageContent) ois.readObject()) != null && ois.read(signature) > 0) {
							boolean signed = verifySignature(signature, content.getEncryptedMessage(),
									content.getUnencryptedTimestamp(), SERVER);
							if (signed) {
								System.out.println("Date: " + new Date(content.getUnencryptedTimestamp()).toString());
								System.out.println("Message: " + decryptionUtil(userId,
										Base64.getDecoder().decode(content.getEncryptedMessage())));
								System.out.println();
							} else {
								System.err.println(
										"Signature verification was not successful for the messages that were received...\n");
							}
						}
					} catch (EOFException e) {
						e.printStackTrace();
					} catch (ClassNotFoundException | IOException e) {
						e.printStackTrace();
					}
				}
			}

		} catch (EOFException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static String askUserToSendMessage() {
		Scanner sc = new Scanner(System.in);
		String encryptedString = null;

		System.out.println("Do you wish to send a message to anyone? [y/n]");
		String yesNo = sc.nextLine();

		if ("yes".startsWith(yesNo.toLowerCase())) {

			System.out.println("Please enter the recipient's user id...");
			String recipientId = sc.nextLine();
			System.out.println("Please enter the message that you want to send to this recipient securely...");
			String message = sc.nextLine();

			encryptedString = Base64.getEncoder()
					.encodeToString(encryptionUtil(SERVER, recipientId.concat(message).getBytes()));

		} else if ("no".startsWith(yesNo.toLowerCase())) {
			System.out.println("Nothing more to do now, therefore exiting the program...\n\n");
		} else {
			System.err.println("Invalid response provided, please enter either y or n...\n\n");
			sc.close();
			return askUserToSendMessage();
		}

		sc.close();
		return encryptedString;
	}

	private static byte[] getSignature(String encryptedString, Long timestamp) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA");
			sig.initSign(getPrivateKey(userId));
			sig.update(encryptedString.getBytes());
			sig.update(ByteBuffer.allocate(Long.BYTES).putLong(timestamp).array());
			return sig.sign();
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static boolean verifySignature(byte[] signature, String base64Message, Long epoch, String user) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(getPublicKey(user));
			sig.update(base64Message.getBytes());
			sig.update(ByteBuffer.allocate(Long.BYTES).putLong(epoch).array());
			return sig.verify(signature);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
		}
		return false;
	}

	private static String convertUserIdToHashedMD5Id(String userId) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(MD5);
			byte[] byteDigest = messageDigest.digest(PREPEND_STRING.concat(userId).getBytes());

			StringBuilder hexBuilder = new StringBuilder();
			for (byte bd : byteDigest) {
				hexBuilder.append(String.format(HEX_FORMAT, bd));
			}

			return hexBuilder.toString();
		} catch (NoSuchAlgorithmException e) {
		}
		return null;
	}

	private static byte[] encryptionUtil(String userId, byte[] byteMessage) {
		try {
			PublicKey pubKey = getPublicKey(userId);

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] raw = cipher.doFinal(byteMessage);

			return raw;
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static String decryptionUtil(String userId, byte[] message) {
		try {
			PrivateKey prvKey = getPrivateKey(userId);

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, prvKey);
			byte[] stringBytes = cipher.doFinal(message);

			return new String(stringBytes, "UTF8");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static PublicKey getPublicKey(String userId) {
		try {
			File f = new File(userId.concat(PUBLIC_KEY));
			byte[] keyBytes = Files.readAllBytes(f.toPath());
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(pubSpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static PrivateKey getPrivateKey(String userId) {
		try {
			File f = new File(userId.concat(PRIVATE_KEY));
			byte[] keyBytes = Files.readAllBytes(f.toPath());
			PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(prvSpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static void initializeHostPortUserId(String[] args) {
		if (args.length != 3) {
			System.out.println("The length of the provided arguments is incorrect!!!");
			System.out.println(
					"Please provide correct arguments that are space-seperated values denoting host, port and userid...");
			return;
		}

		host = args[0];
		port = Integer.parseInt(args[1]);
		userId = args[2];
	}
}
