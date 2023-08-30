import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.Console;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/*
 * Jesse O'Connor
 * 1534760
 */
public class MyTLSFileServer {
    
    public static void main(String args[]) {
        
        if (args.length < 1) {
            System.err.println("usage: MyTLSFileServer <port>\n");
            return;
        }
        
        /*
         * use the getSSF method to get a SSLServerSocketFactory
         * and create out SSLServerSocket, bound to a specified
         * port
         */
        ServerSocketFactory ssf = getSSF();
        SSLServerSocket ss = null;
        try {
            ss = (SSLServerSocket) ssf.createServerSocket(Integer.parseInt(args[0]));
        } catch (NumberFormatException | IOException e) {
            System.err.println(e);
        }
        String EnabledProtocols[] = {"TLSv1.2", "TLSv1.3"};
        ss.setEnabledProtocols(EnabledProtocols);

        SSLSocket s = null;
        String fileName = null;
        try {
            s = (SSLSocket) ss.accept();
            BufferedReader read = new BufferedReader(new InputStreamReader(s.getInputStream()));
            fileName = read.readLine();
            s.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        /*
         * Send img file over socket, using byte buffer
         */
        try {
            byte[] buffer = new byte[1024];
            File file = new File(fileName);
            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            FileInputStream reader = new FileInputStream(file);

            int length = reader.read(buffer);
            while(length != -1) {
                dos.write(buffer);
                dos.flush();
                length = reader.read(buffer);
            }
            dos.close();
            reader.close();
        } catch (IOException e) {
            try {
                s.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }
    
    private static ServerSocketFactory getSSF() {
        SSLServerSocketFactory ssf = null;
        try {
            /*
            * get an SSL Context that speaks some version
            * of TLS, a KeyManager that can hold certs in
            * X.509 format, and a JavaKeyStore (JKS) instance
            */
            SSLContext ctx = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            KeyStore ks = KeyStore.getInstance("JKS");

            /*
            * Get JKS file passphrase from our file of passwords
            */
            Console console = System.console();
            char[] passphrase = console.readPassword("Enter passphrase for server.jks: ");
            
            /*
            * load the keystore file
            */
            ks.load(new FileInputStream("server.jks"), passphrase);

            /*
            * init the KeyManagerFactory with a source
            * of key material.
            */
            kmf.init(ks, passphrase);

            /*
            * initialises the SSL context with the keys
            */
            ctx.init(kmf.getKeyManagers(), null, null);

            ssf = ctx.getServerSocketFactory();


        } catch (NoSuchAlgorithmException | KeyStoreException | IOException
         | CertificateException | UnrecoverableKeyException | KeyManagementException e) {
            System.err.println(e);
        }
        /*
        * get the factory we will use to create our SSLServerSocket
        */

        return ssf;
    }

}
