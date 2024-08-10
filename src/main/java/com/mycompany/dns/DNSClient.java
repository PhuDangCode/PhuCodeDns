package com.mycompany.dns;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class DNSClient {
    private static final int DNS_SERVER_PORT = 53;
    private static final String DNS_SERVER_ADDRESS = "localhost";
    private static final int SOCKET_TIMEOUT = 20000; // 20 seconds

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.print("Enter a domain name or IP address (or type 'exit' to quit): ");
                String input = scanner.nextLine().trim();

                if (input.equalsIgnoreCase("exit")) {
                    System.out.println("Exiting...");
                    break;
                }

                boolean isPtrQuery = isIPAddress(input);
                String query = isPtrQuery ? toPtrRecord(input) : input;

                try (DatagramSocket socket = new DatagramSocket()) {
                    socket.setSoTimeout(SOCKET_TIMEOUT); // Set timeout
                    InetAddress serverAddress = InetAddress.getByName(DNS_SERVER_ADDRESS);

                    byte[] requestPacket = createDNSQuery(query, isPtrQuery);

                    DatagramPacket packet = new DatagramPacket(requestPacket, requestPacket.length, serverAddress, DNS_SERVER_PORT);
                    socket.send(packet);
                    System.out.println("Client sent query: " + query);

                    byte[] buffer = new byte[512];
                    DatagramPacket responsePacket = new DatagramPacket(buffer, buffer.length);
                    socket.receive(responsePacket);

                    // Log raw response data for debugging
                    System.out.println("Raw response data: " + bytesToHex(buffer, responsePacket.getLength()));

                    String response = parseDNSResponse(responsePacket.getData(), responsePacket.getLength(), isPtrQuery);
                    System.out.println("Client received response: \n" + response);
                } catch (Exception e) {
                    System.err.println("An error occurred while processing the DNS query: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    private static boolean isIPAddress(String input) {
        return input.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
    }

    private static String toPtrRecord(String ip) {
        String[] octets = ip.split("\\.");
        return octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0] + ".in-addr.arpa";
    }

    private static byte[] createDNSQuery(String domainName, boolean isPtrQuery) {
        ByteBuffer buffer = ByteBuffer.allocate(512);

        // DNS Header
        buffer.putShort((short) 0x1234);  // ID
        buffer.putShort((short) 0x0100);  // Flags: standard query
        buffer.putShort((short) 1);       // QDCOUNT (number of question entries)
        buffer.putShort((short) 0);       // ANCOUNT (number of answer entries)
        buffer.putShort((short) 0);       // NSCOUNT (number of authority records)
        buffer.putShort((short) 0);       // ARCOUNT (number of additional records)

        // DNS Question
        String[] labels = domainName.split("\\.");
        for (String label : labels) {
            buffer.put((byte) label.length());
            buffer.put(label.getBytes(StandardCharsets.UTF_8));
        }
        buffer.put((byte) 0);  // End of domain name

        buffer.putShort((short) (isPtrQuery ? 12 : 1));  // QTYPE (PTR or A)
        buffer.putShort((short) 1);                      // QCLASS (IN)

        byte[] query = new byte[buffer.position()];
        buffer.flip();
        buffer.get(query);
        return query;
    }

    private static String parseDNSResponse(byte[] response, int length, boolean isPtrQuery) {
        ByteBuffer buffer = ByteBuffer.wrap(response, 0, length);

        // Read DNS Header
        if (buffer.remaining() < 12) {
            return "Invalid response header";
        }
        buffer.getShort();  // ID
        buffer.getShort();  // Flags
        buffer.getShort();  // QDCOUNT
        short ancount = buffer.getShort();  // ANCOUNT
        buffer.getShort();  // NSCOUNT
        buffer.getShort();  // ARCOUNT

        // Skip question section
        skipQuestionSection(buffer);

        // Parse answer section
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ancount; i++) {
            sb. append(parseAnswerRecord(buffer, isPtrQuery)).append("\n");
        }

        return sb.toString();
    }

    private static void skipQuestionSection(ByteBuffer buffer) {
        while (buffer.remaining() > 0 && buffer.get() != 0);  // Skip the name
        if (buffer.remaining() >= 4) {
            buffer.getShort();  // QTYPE
            buffer.getShort();  // QCLASS
        }
    }

    private static String parseAnswerRecord(ByteBuffer buffer, boolean isPtrQuery) {
        if (buffer.remaining() < 12) {
            return "Incomplete answer record";
        }

        StringBuilder sb = new StringBuilder();

        int nameStartPos = buffer.position();
        String name = decodeName(buffer, nameStartPos);
        sb.append("Name: ").append(name).append("\n");

        short type = buffer.getShort();
        sb.append("Type: ").append(type).append("\n");

        buffer.getShort();  // CLASS
        buffer.getInt();    // TTL
        short rdlength = buffer.getShort();
        sb.append("RDLENGTH: ").append(rdlength).append("\n");

        if (buffer.remaining() < rdlength) {
            sb.append("Incomplete RDATA: remaining=").append(buffer.remaining()).append(", expected=").append(rdlength).append("\n");
            return sb.toString();
        }

        byte[] rdata = new byte[rdlength];
        buffer.get(rdata);

        if (type == 1) { // A record
            sb.append("Address: ").append(decodeARecord(rdata)).append("\n");
        } else if (type == 12) { // PTR record
            sb.append("PTR: ").append(decodeName(ByteBuffer.wrap(rdata), 0)).append("\n");
        } else {
            sb.append("RDATA: ").append(new String(rdata, StandardCharsets.UTF_8)).append("\n");
        }

        return sb.toString();
    }

    private static String decodeARecord(byte[] rdata) {
        return (rdata[0] & 0xFF) + "." + (rdata[1] & 0xFF) + "." + (rdata[2] & 0xFF) + "." + (rdata[3] & 0xFF);
    }

    private static String decodeName(ByteBuffer buffer, int offset) {
        StringBuilder name = new StringBuilder();
        int originalPosition = buffer.position();
        boolean jumped = false;

        while (true) {
            if (offset >= buffer.limit()) {
                break;
            }
            byte length = buffer.get(offset);
            if (length == 0) {
                offset++;
                break;
            }

            if ((length & 0xC0) == 0xC0) { // Compression pointer
                if (!jumped) {
                    originalPosition = offset + 2;
                    jumped = true;
                }
                int pointer = ((length & 0x3F) << 8) | (buffer.get(offset + 1) & 0xFF);
                offset = pointer;
            } else {
                offset++;
                byte[] label = new byte[length];
                buffer.position(offset);
                if (buffer.remaining() < length) {
                    break; // Avoid BufferUnderflowException
                }
                buffer.get(label);
                name.append(new String(label, StandardCharsets.UTF_8)).append('.');
                offset += length;
            }
        }

        if (!jumped) {
            buffer.position(offset);
        } else {
            buffer.position(originalPosition);
        }

        return name.toString();
    }

    private static String bytesToHex(byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString();
    }
}
