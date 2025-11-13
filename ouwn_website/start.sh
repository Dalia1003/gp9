#!/bin/bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask app
export FLASK_APP=app.py
export FLASK_ENV=production
flask run --host=0.0.0.0 --port=$PORT
