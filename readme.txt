step 1 -- in mac

mkdir webssh && cd webssh

python3 -m venv .venv

source .venv/bin/activate

brew install putty


step 2 -- in created local folder


pip install flask flask-sock paramiko gevent gevent-websocket


step 3 -- it will run on port http://127.0.0.1:5000 

python app.py