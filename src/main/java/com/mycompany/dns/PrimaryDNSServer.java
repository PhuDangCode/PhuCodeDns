package com.mycompany.dns;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class PrimaryDNSServer {
    private static final int PORT = 53;
    private static final String SECONDARY_SERVER_ADDRESS = "localhost";
    private static final int SECONDARY_SERVER_PORT = 5358;
    private static final String DNS_TABLE_FILE = "C:\\Users\\luan1\\Desktop\\DNS\\DNS_Data\\primary_dns_table.txt";
    private static final int THREAD_POOL_SIZE = 10;
    private static final int QUEUE_CAPACITY = 50;

    public static void main(String[] args) {
        Map<String, DNSRecord> dnsTable = loadDNSTable(DNS_TABLE_FILE);
        ExecutorService executorService = new ThreadPoolExecutor(
                THREAD_POOL_SIZE,
                THREAD_POOL_SIZE,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY)
        );

        try (DatagramSocket socket = new DatagramSocket(PORT)) {
            System.out.println("Primary DNS Server is running...");

            while (true) {
                byte[] buffer = new byte[512];
                DatagramPacket requestPacket = new DatagramPacket(buffer, buffer.length);
                socket.receive(requestPacket);

                executorService.execute(() -> handleRequest(socket, requestPacket, dnsTable));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            executorService.shutdown();
        }
    }

    private static void handleRequest(DatagramSocket socket, DatagramPacket requestPacket, Map<String, DNSRecord> dnsTable) {
        try {
            byte[] requestData = requestPacket.getData();
            ByteBuffer requestBuffer = ByteBuffer.wrap(requestData);

            // Parse DNS Query
            requestBuffer.getShort(); // Transaction ID
            requestBuffer.getShort(); // Flags
            requestBuffer.getShort(); // Questions
            requestBuffer.getShort(); // Answer RRs
            requestBuffer.getShort(); // Authority RRs
            requestBuffer.getShort(); // Additional RRs

            String queryName = parseDomainName(requestBuffer);
            short queryType = requestBuffer.getShort();
            requestBuffer.getShort(); // Query class (IN)

            System.out.println("Primary Server received query: " + queryName);

            DNSRecord record = dnsTable.get(queryName + " " + queryType);

            if (record == null) {
                System.out.println("Primary Server forwarding query to Secondary Server for: " + queryName);
                // Forward the query to the secondary server and then return
                if (querySecondaryServer(socket, requestPacket)) {
                    System.out.println("Primary Server forwarded query to Secondary Server for: " + queryName);
                }
                return;
            }

            byte[] responseBytes = createDNSResponse(requestData, record.value, queryType);
            DatagramPacket responsePacket = new DatagramPacket(responseBytes, responseBytes.length, requestPacket.getAddress(), requestPacket.getPort());
            socket.send(responsePacket);

            System.out.println("Primary Server sent response: " + record.value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Map<String, DNSRecord> loadDNSTable(String filePath) {
        Map<String, DNSRecord> dnsTable = new HashMap<>();
        try {
            Files.lines(Paths.get(filePath)).forEach(line -> {
                String[] parts = line.split("\\s+");
                if (parts.length >= 5) {
                    String key = parts[0] + " " + getTypeCode(parts[1]);
                    DNSRecord record = new DNSRecord(parts[0], parts[1], Integer.parseInt(parts[2]), parts[3], parts[4]);
                    dnsTable.put(key, record);
                    System.out.println("Loaded record: " + key + " -> " + parts[4]);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dnsTable;
    }

    private static String parseDomainName(ByteBuffer buffer) {
        StringBuilder domainName = new StringBuilder();
        while (true) {
            byte length = buffer.get();
            if (length == 0) {
                break;
            }
            if ((length & 0xC0) == 0xC0) { // Pointer
                int pointer = ((length & 0x3F) << 8) | (buffer.get() & 0xFF);
                int currentPosition = buffer.position();
                buffer.position(pointer);
                domainName.append(parseDomainName(buffer));
                buffer.position(currentPosition);
                break;
            } else {
                byte[] label = new byte[length];
                buffer.get(label);
                domainName.append(new String(label, StandardCharsets.UTF_8)).append('.');
            }
        }
        return domainName.toString();
    }

    private static byte[] createDNSResponse(byte[] requestData, String response, short queryType) {
        int domainNameLength = getDomainNameLength(requestData, 12);
        ByteBuffer buffer;

        if (queryType == 1) { // A record
            int bufferSize = 12 + domainNameLength + 4 + domainNameLength + 10 + 4; // IP address is 4 bytes
            buffer = ByteBuffer.allocate(bufferSize);

            // DNS Header
            buffer.put(requestData, 0, 2); // Transaction ID
            buffer.putShort((short) 0x8180); // Flags: standard query response, no error
            buffer.putShort((short) 1); // Questions
            buffer.putShort((short) 1); // Answer RRs
            buffer.putShort((short) 0); // Authority RRs
            buffer.putShort((short) 0); // Additional RRs

            // DNS Question
            buffer.put(requestData, 12, domainNameLength + 4); // Domain name, QTYPE, and QCLASS

            // DNS Answer
            buffer.put(requestData, 12, domainNameLength); // Domain name
            buffer.putShort(queryType); // TYPE
            buffer.putShort((short) 1); // CLASS
            buffer.putInt(3600); // TTL
            buffer.putShort((short) 4); // RDLENGTH (IP address is always 4 bytes)

            // Encode IP address
            String[] octets = response.split("\\.");
            for (String octet : octets) {
                buffer.put((byte) Integer.parseInt(octet));
            }

        } else if (queryType == 12) { // PTR record
            byte[] responseBytes = encodeDomainName(response);
            int bufferSize = 12 + domainNameLength + 4 + domainNameLength + 10 + responseBytes.length;
            buffer = ByteBuffer.allocate(bufferSize);

            // DNS Header
            buffer.put(requestData, 0, 2); // Transaction ID
            buffer.putShort((short) 0x8180); // Flags: standard query response, no error
            buffer.putShort((short) 1); // Questions
            buffer.putShort((short) 1); // Answer RRs
            buffer.putShort((short) 0); // Authority RRs
            buffer.putShort((short) 0); // Additional RRs

            // DNS Question
            buffer.put(requestData, 12, domainNameLength + 4); // Domain name, QTYPE, and QCLASS

            // DNS Answer
            buffer.put(requestData, 12, domainNameLength); // Domain name
            buffer.putShort(queryType); // TYPE
            buffer.putShort((short) 1); // CLASS
            buffer.putInt(3600); // TTL
            buffer.putShort((short) responseBytes.length); // RDLENGTH

            // PTR Data
            buffer.put(responseBytes);

        } else {
            throw new IllegalArgumentException("Unsupported query type: " + queryType);
        }

        byte[] responseBytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(responseBytes);
        return responseBytes;
    }

    private static byte[] encodeDomainName(String domainName) {
        String[] labels = domainName.split("\\.");
        ByteBuffer buffer = ByteBuffer.allocate(256); // Max domain length is 255 bytes
        for (String label : labels) {
            buffer.put((byte) label.length());
            buffer.put(label.getBytes(StandardCharsets.UTF_8));
        }
        buffer.put((byte) 0); // End of domain name
        byte[] result = new byte[buffer.position()];
        buffer.flip();
        buffer.get(result);
        return result;
    }

    private static int getDomainNameLength(byte[] data, int offset) {
        int length = 0;
        while (data[offset + length] != 0) {
            length += data[offset + length] + 1;
        }
        return length + 1; // Include null byte
    }

    private static boolean querySecondaryServer(DatagramSocket socket, DatagramPacket requestPacket) {
        try (DatagramSocket secondarySocket = new DatagramSocket()) {
            InetAddress secondaryServerAddress = InetAddress.getByName(SECONDARY_SERVER_ADDRESS);

            // Forward the entire request packet to the secondary server
            DatagramPacket forwardPacket = new DatagramPacket(requestPacket.getData(), requestPacket.getLength(), secondaryServerAddress, SECONDARY_SERVER_PORT);
            secondarySocket.send(forwardPacket);

            System.out.println("Primary Server forwarding query to Secondary Server for: " + parseDomainName(ByteBuffer.wrap(requestPacket.getData(), 12, requestPacket.getLength() - 12)));

            byte[] buffer = new byte[512];
            DatagramPacket responsePacket = new DatagramPacket(buffer, buffer.length);
            secondarySocket.receive(responsePacket);

            DatagramPacket clientResponsePacket = new DatagramPacket(responsePacket.getData(), responsePacket.getLength(), requestPacket.getAddress(), requestPacket.getPort());
            socket.send(clientResponsePacket);

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static short getTypeCode(String type) {
        switch (type) {
            case "A": return 1;
            case "NS": return 2;
            case "CNAME": return 5;
            case "MX": return 15;
            case "PTR": return 12;
            case "AAAA": return 28;
            default: return 0;
        }
    }
}
