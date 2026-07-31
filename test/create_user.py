import requests

url = "https://api.dataimpulse.com/reseller/sub-user/create"

data = {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vYXBpLmRhdGFpbXB1bHNlLmNvbS9yZXNlbGxlci91c2VyL3Rva2VuL2dldCIsImlhdCI6MTc3ODc5ODE3MCwiZXhwIjoxNzc4ODg0NTcwLCJuYmYiOjE3Nzg3OTgxNzAsImp0aSI6ImFmRGVFdVJ2M2lXeGplM08iLCJzdWIiOiIyMTA4MTEiLCJwcnYiOiI4MDE2ZDQxNmFjYTkyODY1Zjg4ZTU4ODM0MzljNjk5MWYzODM0Y2Y1In0.3-0GEQqgYRy_n_D7u-Hp-A-qGT4iAgPJWpEnwi1GJ5E",
    "label": "teste user",
    "sticky_range": {
        "start": 11001,
        "end": 20000
    },
    "threads": 100
}

response = requests.post(url, json=data)

print(response.json())