# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
import os
from analyzer.url_check import check_url
from analyzer.url_check import check_url
from analyzer.text_check import check_text
from analyzer.password_check import check_password

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check-url", methods=["POST"])
def api_check_url():
    data = request.get_json()
    url = data.get("url", "")
    if not url.strip():
        return jsonify({
            "nivel": "amarillo",
            "puntuacion": 0,
            "alertas": ["No URL was provided."],
            "mensaje": "Please paste a link to analyze it.",
            "confidence": 0,
            "checks_passed": 0,
            "total_checks": 0
        })
    return jsonify(check_url(url))


@app.route("/api/check-text", methods=["POST"])
def api_check_text():
    data = request.get_json()
    texto = data.get("texto", "")
    if not texto.strip():
        return jsonify({
            "nivel": "amarillo",
            "puntuacion": 0,
            "alertas": ["No message was provided."],
            "categorias": {},
            "mensaje": "Please paste the complete message to analyze it.",
            "confidence": 0,
            "total_signals": 0
        })
    return jsonify(check_text(texto))


@app.route("/api/check-password", methods=["POST"])
def api_check_password():
    data = request.get_json()
    password = data.get("password", "")
    return jsonify(check_password(password))


if __name__ == "__main__":
app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
