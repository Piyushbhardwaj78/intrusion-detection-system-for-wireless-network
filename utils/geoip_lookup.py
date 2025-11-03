import geoip2.database
import os

db_path = os.path.join("geo", "GeoLite2-City.mmdb")
reader = geoip2.database.Reader(db_path)

def lookup_ip(ip_address):
    try:
        response = reader.city(ip_address)
        return {
            "country": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude
        }
    except:
        return {"country": "Unknown", "city": "Unknown"}