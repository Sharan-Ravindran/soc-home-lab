```python
from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>ACME Employee Portal</h1>
    <p>Welcome to the internal employee portal.</p>
    <a href="/login">Login</a>
"""


@app.route("/login")
def login():
    return """
    <h1>Login</h1>
    <form>
        <input type="text" placeholder="Username">
        <input type="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```
