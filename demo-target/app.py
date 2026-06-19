from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        "status": "healthy",
        "service": "ArmorGuard Demo Target",
        "message": "Demo target is running and ready to accept security scans."
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
