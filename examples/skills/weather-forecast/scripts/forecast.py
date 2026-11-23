import sys
import requests

city = sys.argv[1]
geo = requests.get("https://geocoding-api.open-meteo.com/v1/search", params={"name": city, "count": 1}).json()
place = geo["results"][0]
forecast = requests.get(
    "https://api.open-meteo.com/v1/forecast",
    params={"latitude": place["latitude"], "longitude": place["longitude"], "daily": "temperature_2m_max"},
).json()
print(forecast["daily"])
