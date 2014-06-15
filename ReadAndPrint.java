import java.io.*;
import java.util.*;

public class ReadAndPrint{
  static int KEY_LEN=256;
  public static void main(String[] args){
    String fileName=args[0];
    try{
      byte[] bytes=readByteFromFile(new File(fileName));
      byte[] signature=Arrays.copyOfRange(bytes,0,KEY_LEN);
      byte[] cipher_text=Arrays.copyOfRange(bytes,KEY_LEN,bytes.length);
      System.out.println("Signature Hex:");
      for(byte b : signature){
        System.out.print(String.format("%02X ",b));
      }
      System.out.println();
      System.out.println("Cipher_text Hex:");
      for(byte b : cipher_text){
        System.out.print(String.format("%02X ",b));
      }
      System.out.println();


    }catch(Exception e){
      System.out.println(e.getMessage());
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

}
