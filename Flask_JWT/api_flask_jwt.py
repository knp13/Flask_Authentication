from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisismysecretkey4987'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({'message':'Token is missing ! '}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid! '}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/common')
def common():
    return jsonify({'message':'Anyone can view this'})

@app.route('/authenticated')
@token_required
def authenticated():
    return jsonify({'message':'Only people with valid token can view this.'})

@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password == "password":
        token = jwt.encode({'user':auth.username, 'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return make_response('Could Not Verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})

if __name__ == '__main__':
    app.run(debug=True)
