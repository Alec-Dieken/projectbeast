from projectbeast import init_app

app = init_app()

from projectbeast import socketio

if __name__ == '__main__':
    
    socketio.run(app)
