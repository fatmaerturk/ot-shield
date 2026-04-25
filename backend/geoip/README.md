# GeoIP Database

Place `GeoLite2-City.mmdb` in this folder to enable offline IP → country/city lookups.

## How to get it (free, one-time)

1. Go to https://www.maxmind.com/en/geolite2/signup and create a free account.
2. Sign in → **Download Databases** → pick **GeoLite2 City** → click the **Download GZIP** link.
3. Extract the `.tar.gz` (or `.zip`). Inside there's `GeoLite2-City.mmdb`.
4. Copy that single `.mmdb` file into this folder so you end up with:

   ```
   backend/geoip/GeoLite2-City.mmdb
   ```

5. Restart the Spring Boot backend. You should see this line in the console:

   ```
   INFO  GeoIpService : GeoIP database loaded: .../backend/geoip/GeoLite2-City.mmdb
   ```

## If the file is missing

No crash. The backend logs a warning and every geolocation call returns `UNKNOWN`.
The Attack Intelligence page still works — the "Top Countries" / map sections just
stay empty until the DB is in place.

## Updating

MaxMind publishes a refreshed DB every Tuesday. To update, re-download and replace
the `.mmdb` file. No code change needed.

## License

GeoLite2 is distributed by MaxMind under their own terms — **do not commit the
`.mmdb` file to this repository**. It's gitignored.
