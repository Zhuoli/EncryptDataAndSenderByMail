// Amirali Sanatinia amirali@ccs.neu.edu
// Network Security JCE demo
// Usage: jave Encrypt PUBLIC_KEY.der PRIVATE_KEY.der PLAINTEXT

import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.util.*;
public class Decrypt {
	static int KEY_LEN=256;
	static boolean DEBUG = true;
	byte[] signature=null;
	byte[] cipher_text=null;
	byte[] aesKeyEncyrpted=null;
	public static void main(String[] args) throws Exception {
		if(args.length<5){
			System.out.println("usage Error: ");
			System.exit(0);
		}
		Decrypt instance=new Decrypt(args[1],args[2],args[3],args[4]);

     }
     /** Init ***/
     public Decrypt(String public_key_filename, String private_key_filename,String plaintext_filename,String cipher_filename) {
        if(isDecryptInputError(public_key_filename,private_key_filename,cipher_filename))
             System.exit(0);
        try{
        	getKeyAndCipher(cipher_filename);
        	this.decrypt(public_key_filename,private_key_filename,plaintext_filename,cipher_filename);

        }catch(Exception e){
        	System.out.println("Error: " + e.getMessage());
        	System.exit(0);
        }

     }
     private void decrypt(String public_key_filename, String private_key_filename,String plaintext_filename,String cipher_filename)throws Exception{

		// Public, private and signature instances

		Cipher secCipher = Cipher.getInstance("AES");
		SecretKey aesKey=null;
		// verify and decrypt aes key
		try{
			aesKey=getSecKey(public_key_filename,private_key_filename);
		}catch(Exception e){
			System.out.println(e.getMessage());
			System.exit(0);
		}
		// decryt cipher text
     	secCipher.init(Cipher.DECRYPT_MODE,aesKey);
     	byte[] plaintext=secCipher.doFinal(cipher_text);
     	if(DEBUG)
	     	for(byte b : plaintext){
	     		System.out.print((char)b);
	     	}
	    


     }
     private SecretKey getSecKey(String public_key_filename, String private_key_filename)throws Exception{
		Signature sig = Signature.getInstance("SHA512withRSA");
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
     	Cipher publicChiper = Cipher.getInstance("RSA");
		X509EncodedKeySpec publicSpec;
		PKCS8EncodedKeySpec privateSpec;
		PrivateKey prvKey;
		PublicKey pubKey;
		byte[] privateKey=null,publicKey=null;
		SecretKey aesKey=null;
	    // read public key from file
     	try{
     		privateKey = readByteFromFile(new File(private_key_filename));
     	}catch(Exception e){
     		System.out.println("readByteFromFile() Error: " + e.getMessage());
     		System.exit(0);
     	}
     	// get public key
		privateKey = readByteFromFile(new File(private_key_filename));
		publicKey = readByteFromFile(new File(public_key_filename));
		privateSpec = new PKCS8EncodedKeySpec(privateKey);
		publicSpec = new X509EncodedKeySpec(publicKey);
		prvKey = rsaKeyFactory.generatePrivate(privateSpec);
		pubKey = rsaKeyFactory.generatePublic(publicSpec);
     	// verify
     	if(!verify(sig,pubKey))
     		System.exit(0);
     	//Decrypt
     	publicChiper.init(Cipher.UNWRAP_MODE, prvKey);
     	aesKey = (SecretKey)publicChiper.unwrap(aesKeyEncyrpted,"AES",Cipher.SECRET_KEY);
     	return aesKey;

     }
     private boolean verify(Signature sig,PublicKey pubKey){
     	if(sig==null || pubKey==null){
     		System.out.println("verify() input error.");
     		System.exit(0);
     	}

     	try{
	     	//This method puts the Signature object in the VERIFY state.
	     	sig.initVerify(pubKey);
	     	//The data is passed to the object by calling one of the update methods:
	     	sig.update(cipher_text);
	     	sig.update(this.aesKeyEncyrpted);
	     	boolean ok=sig.verify(signature);
	     	System.out.println("Verify Processing Info: ");
      		System.out.println("Number of input bytes = "+cipher_text.length);
      		System.out.println("signature bytes = "+signature.length);
     		System.out.println("Verification result = "+ok);
     		return ok;
	     }catch(Exception e){
	     	System.out.println("Sig verify error: " + e.getMessage());
	     	System.exit(0);
	     }
	     return true;
     }
	 public  void getKeyAndCipher(String fileName)throws Exception{

	      byte[] bytes=readByteFromFile(new File(fileName));
	      this.signature=Arrays.copyOfRange(bytes,0,KEY_LEN);
	      this.aesKeyEncyrpted=Arrays.copyOfRange(bytes,KEY_LEN,2*KEY_LEN);
	      this.cipher_text=Arrays.copyOfRange(bytes,2*KEY_LEN,bytes.length);

	      if(DEBUG){
		      System.out.println("Signature Hex:");
		      for(byte b : signature){
		        System.out.print(String.format("%02X ",b));
		      }   
		      System.out.println();
		      System.out.println("aesKeyEncyrpted Hex:");
		      for(byte b : aesKeyEncyrpted){
		        System.out.print(String.format("%02X ",b));
		      }   
		      System.out.println();
		      System.out.println("Cipher_text Hex:");
		      for(byte b : cipher_text){
		        System.out.print(String.format("%02X ",b));
		      }   
		      System.out.println();
		  }

	  }
	  private static byte[] readByteFromFile(File f) throws Exception{

	    if(f.length() > Integer.MAX_VALUE)
	      System.out.println("File is too large");

	    byte[] buffer = new byte[(int)f.length()];
	    InputStream ios = new FileInputStream(f);
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
	  private static boolean isDecryptInputError(String public_key_filename, String private_key_filename,String cipher_filename){
            if(!new File(public_key_filename).isFile()){
              System.out.println("File: " + public_key_filename + " not exist or not a file");
              return true;
            }   
            if(!new File(private_key_filename).isFile()){
              System.out.println("File: " + private_key_filename + " not exist or not a file");
              return true;
            }  
            if(!new File(cipher_filename).isFile()){
              System.out.println("File: " + cipher_filename + " not exist or not a file");
              return true;
            }  

          return false;
        }  
}