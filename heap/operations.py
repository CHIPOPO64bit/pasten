from base64 import b64decode


def upload_video(db, name, data):
    db['videos'][name] = b64decode(data)

def upload_text(db, name, data):
    db['text'][name] = data.split('\n')

def upload_image(db, name, data):
    db['images'][name] = b64decode(data)
