from server.server import Server
import time


if __name__ == '__main__':
    import sys

    try:
        port = int(sys.argv[1])
        file = str(sys.argv[2])
        dstip = str(sys.argv[3])
    except ValueError:
        raise ValueError('port value should be integer')

    while True:
        server = Server(port, file, dstip)
        try:
            server.setup()
            while True:
                if not server._rtp_send_thread.is_alive():
                    time.sleep(0.5)
                    break
            # server._rtp_send_thread.join()
        except ConnectionError as e:
            print(f"Connection reset: {e}")
            break
        except KeyboardInterrupt:
            print("-----------------")
            break
