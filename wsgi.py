from projectbeast import init_app

app = init_app()

from projectbeast import socketio

if __name__ == '__main__':
    # app.run(host='0.0.0.0', debug=True)
    socketio.run(app, debug=True)
