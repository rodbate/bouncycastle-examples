package geoip;


import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.*;

import java.io.File;
import java.net.InetAddress;
import java.net.URL;
import java.util.Collections;

/**
 * <a src="https://dev.maxmind.com/geoip/geoip2/geolite2/"></a>
 */

public class GeoIpMain {

    public static void main(String[] args) throws Exception {

        //此种方法废弃  ：将会将整个文件全部load进内存  浪费内存
        //InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("GeoLite2-City.mmdb");

        //optimize 使用 mmap 内存映射的方式
        URL resource = Thread.currentThread().getContextClassLoader().getResource("GeoLite2-City.mmdb");
        if (resource == null) {
            System.exit(-1);
        }
        File database = new File(resource.toURI());

        DatabaseReader reader = new DatabaseReader.Builder(database).locales(Collections.singletonList("zh-CN")).build();

        InetAddress ipAddress = InetAddress.getByName("183.14.30.34");

        CityResponse response = reader.city(ipAddress);

        Country country = response.getCountry();
        System.out.println(country.getIsoCode());
        System.out.println(country.getName());

        Subdivision subdivision = response.getMostSpecificSubdivision();
        System.out.println(subdivision.getName());
        System.out.println(subdivision.getIsoCode());

        City city = response.getCity();
        System.out.println(city.getName());

        Postal postal = response.getPostal();
        System.out.println(postal.getCode());

        Location location = response.getLocation();
        System.out.println(location.getLatitude());
        System.out.println(location.getLongitude());

        reader.close();

    }
}
