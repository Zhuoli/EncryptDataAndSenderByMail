// Amirali Sanatinia amirali@ccs.neu.edu
// Network Security JCE demo
// Usage: jave Encrypt PUBLIC_KEY.der PRIVATE_KEY.der PLAINTEXT

import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;

public class Encrypt {

	public static void main(String[] args) throws Exception {

		String public_key_filename, private_key_filename, plaintext_file,output_file;
                // input error halding
                if(isInputError(args))
                    System.exit(0);
		// Public, private and signature instances
		Cipher publicChiper = Cipher.getInstance("RSA");
		Cipher secCipher = Cipher.getInstance("AES");
		Signature sig = Signature.getInstance("SHA512withRSA");
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		Key aesKey;
		PKCS8EncodedKeySpec privateSpec;
		X509EncodedKeySpec publicSpec;
		PrivateKey prvKey;
		PublicKey pubKey;
		
		// byte representation of parameters and IV
		byte[] iv, cipherText, publicKey, plainText, privateKey, signature, aesKeyEncyrpted;

		// Encrypting files
                // public file name
		public_key_filename = args[0];
                 // private file name
		private_key_filename = args[1];
		// plaintext_file name
		plaintext_file = args[2];
                // output_file name
                output_file=args[3];
				
		
		
                /*********** Symmetric Encryption *************/	
		// Symmetric (AES) key generation
		KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
		aesKey = aesKeyGen.generateKey();
		// read bytes from the file
		plainText = readByteFromFile(new File(plaintext_file));
		// setup IV key with random data and encrypt the file using AES key.
		secCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		iv = secCipher.getIV();
		cipherText = secCipher.doFinal(plainText);
		
                /*************  RSA Encryption *****************/
                // init RSA keys
		privateKey = readByteFromFile(new File(private_key_filename));
		publicKey = readByteFromFile(new File(public_key_filename));
		privateSpec = new PKCS8EncodedKeySpec(privateKey);
		publicSpec = new X509EncodedKeySpec(publicKey);
		prvKey = rsaKeyFactory.generatePrivate(privateSpec);
		pubKey = rsaKeyFactory.generatePublic(publicSpec);

		publicChiper.init(Cipher.WRAP_MODE, pubKey);
        // encrypt AESkey
		aesKeyEncyrpted = publicChiper.wrap(aesKey);

		sig.initSign(prvKey);
		//sig.update(iv);
		sig.update(cipherText);
		sig.update(aesKeyEncyrpted);
		signature = sig.sign();
		/** write to file **/
		// write signature
		System.out.println("Signature in HEX");
        System.out.println("Length: "+ signature.length);
		for (byte b : signature){
			System.out.print(String.format("%02X ", b));
		}
        writeByteToFile(new File(output_file),signature);
        // write AES key
        System.out.println("\nAES encrypted key in HEX");
                System.out.println("Length: "+ aesKeyEncyrpted.length);
		for (byte b : aesKeyEncyrpted){
			System.out.print(String.format("%02X ", b));
		}
        appendByteToFile(new File(output_file),aesKeyEncyrpted);
        // write cipher text
		System.out.println("\nCiphter Text");
		for (byte b : cipherText){
			System.out.print(String.format("%02X ", b));
		}
		System.out.println();
        appendByteToFile(new File(output_file),cipherText);
  }

        /**********/
        private static boolean isInputError(String[] args){
          int arg_len=4;
          if(args.length<arg_len){
            System.out.println("Input arguments less than 3, please try again.");
            return true;
          }
          for(int i=0;i<arg_len-1;i++){
            if(!new File(args[i]).isFile()){
              System.out.println("File: " + args[i] + " not exist or not a file");
              return true;
            }

          }

          return false;
        }

	// read bytes from a file
	private static byte[] readByteFromFile(File f) throws Exception {

		if (f.length() > Integer.MAX_VALUE)
			System.out.println("File is too large");

		byte[] buffer = new byte[(int) f.length()];
		InputStream ios = new FileInputStream(f);;
		DataInputStream dis = new DataInputStream(ios);
		dis.readFully(buffer);
		dis.close();
		ios.close();

		return buffer;
	}
        private static boolean writeByteToFile(File f,byte[] bytes) throws Exception{
          FileOutputStream stream = new FileOutputStream(f);
          try{
              stream.write(bytes);
          }finally{
              stream.close();
          }
              return true; 
        }
        private static boolean appendByteToFile(File f,byte[] bytes) throws Exception{
          FileOutputStream stream = new FileOutputStream(f,true);
          try{
              stream.write(bytes);
          }finally{
              stream.close();
          }
              return true; 
        }
}
