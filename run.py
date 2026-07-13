from app import create_app


app = create_app()


if __name__ == "__main__":
    # Deliberately loopback-only. Do not change this for a public deployment.
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

