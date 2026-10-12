
package com.riskauth.risk_auth.context;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CountryResponse;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.net.InetAddress;

@Slf4j
@Service
public class GeoIpService {

    @Value("${app.geoip.db-path:}")
    private String dbPath;

    private DatabaseReader reader;

    @PostConstruct
    void init() {
        if (dbPath == null || dbPath.isBlank()) {
            log.warn("GeoIP database not configured - country will be UNKNOWN");
            return;
        }

        try {
            reader = new DatabaseReader.Builder(new File(dbPath)).build();
            log.info("GeoIP database loaded from {}", dbPath);
        } catch (Exception e) {
            log.warn("Could not load GeoIP database: {}", e.getMessage());
        }
    }

    public String getCountry(String ip) {
        // Only parse literal IPs, so a fake header can't trigger a DNS lookup
        if (ip == null || !ip.matches("^[0-9a-fA-F:.]+$")) {
            return "UNKNOWN";
        }

        try {
            InetAddress addr = InetAddress.getByName(ip);

            if (addr.isLoopbackAddress()
                    || addr.isSiteLocalAddress()
                    || addr.isAnyLocalAddress()) {
                return "LOCAL";
            }

            if (reader == null) {
                return "UNKNOWN";
            }

            CountryResponse response = reader.country(addr);
            String code = response.getCountry().getIsoCode();

            return code != null ? code : "UNKNOWN";
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }
}
