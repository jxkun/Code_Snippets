package jdk.thread.pool.demo;

import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class SimpleHttpServerTest {

    @Test
    public void testServer() throws Exception {
        SimpleHttpServer simpleHttpServer = new SimpleHttpServer();
        simpleHttpServer.setBasePath("D:/www");
        simpleHttpServer.setPort(80);
        simpleHttpServer.start();

        System.in.read();
    }

    @Test
    public void testIntAddress() throws UnknownHostException {
        InetAddress localHost = InetAddress.getLocalHost();
        System.out.println(localHost.getAddress() + " | " + localHost.getHostAddress());
    }
}
