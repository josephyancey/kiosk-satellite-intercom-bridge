package dev.yancey.intercombridge;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/** What the bridge needs of mDNS: look for a service type, and advertise one. */
interface Mdns {
    final class Service {
        final String instance, address;
        final int port;
        final Map<String, String> txt;

        Service(String instance, String address, int port, Map<String, String> txt) {
            this.instance = instance;
            this.address = address;
            this.port = port;
            this.txt = txt;
        }

        String txt(String key) {
            String v = txt.get(key);
            return v == null ? "" : v;
        }
    }

    /** The services of type ("_name._tcp") that answer within lookMs. */
    List<Service> browse(String type, long lookMs) throws IOException, InterruptedException;

    /** Advertises a service on this device until the result is closed. */
    Closeable advertise(String instance, String type, int port, Map<String, String> txt) throws IOException;
}
