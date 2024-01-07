import requests

# this is how you try consume data directly in python
response = requests.get('http://127.0.0.1:8000/trial/drinks/')
print(response.json())
print('testing')
