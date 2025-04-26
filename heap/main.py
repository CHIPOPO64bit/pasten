from flask import Flask, request, render_template
from base64 import b64encode, b64decode
import operations
from compound import Compound
from functools import wraps
import base64


def is_allowed(s):
    if isinstance(s, str):
        s = s.encode()
    if not isinstance(s, bytes):
        raise ValueError('Only bytes and strings are allowed')
    if b'flag' in s:
        raise ValueError('You will not even reach the flag')
    if b'admin' in s:
        raise ValueError('The admin directory is a no-no')

USER_DATA = {
    'videos': {},
    'text': {},
    'images': {}
}

def upload_wrapper(upload_func):
    @wraps(upload_func)
    def func(name, data):
        is_allowed(name)
        is_allowed(data)
        return upload_func(USER_DATA, name, data)

    return func

def read_file(file_name):
    with open(file_name, 'rb') as f:
        return f.read()


DATABASE = {
    'global_settings': {'volume': 100},
    'operations': {
        'video': upload_wrapper(operations.upload_video),
        'text': upload_wrapper(operations.upload_text),
        'image': upload_wrapper(operations.upload_image),
    },
    'public': {
        'cat': b64encode(read_file('static/cat.jpg')),
        'space': b64encode(read_file('static/space.mp4')),
        'bee': read_file('static/bee.txt').decode(),
    },
    'status' : 'nothing'
}

def build_kwargs(query):
    if query.encoded == True:
        kwargs = {
            query.file_name.arg :convert_to_immutable(query.file_name.value),
            query.data.arg : base64.b64decode(query.data.value),
        }
    else:
        kwargs = {
            query.file_name.arg :convert_to_immutable(query.file_name.value),
            query.data.arg : convert_to_immutable(query.data.value),
        }
    return kwargs


def convert_to_immutable(a):
    if isinstance(a, list):
        return tuple(a)
    return a

def run_query(request):
    config = Compound.load_from_dict(DATABASE, input_filter=is_allowed)
    # convert string to bytes...
    config.user = Compound.load_from_dict(request, input_filter=is_allowed)
    for query in config.user.queries:
        database_function = getattr(config.operations, query.name)
        if query.data.arg is None:
            status = database_function(convert_to_immutable(query.data.value), convert_to_immutable(query.file_name.value))
        else:
            kwargs = build_kwargs(query)
            status = database_function(**kwargs)
        # log status in db, for monitoring...
        config._underlying_dict["status"] = status


app = Flask(__name__)


@app.route('/upload', methods=['POST'])
def upload():
    run_query(request.json)
    return 'Request completed successfully', 200


@app.route('/video/<name>')
def video(name):
    return render_template('video.html', data=b64encode(USER_DATA['videos'][name]).decode())

@app.route('/text/<name>')
def text(name):
    return render_template('text.html', data=USER_DATA['text'][name])

@app.route('/image/<name>')
def image(name):
    return render_template('image.html', data=b64encode(USER_DATA['images'][name]).decode())

@app.errorhandler(500)
def server_error(e):
    return str(e.original_exception), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
