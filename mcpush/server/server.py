import socket
from time import sleep
from threading import Thread
from typing import Union

from utils.video_stream import VideoStream
from utils.rtsp_packet import RTSPPacket
from utils.rtp_packet import RTPPacket


class Server:
    FRAME_PERIOD = 1000//VideoStream.DEFAULT_FPS  # in milliseconds
    SESSION_ID = '123456'

    DEFAULT_CHUNK_SIZE = 4096

    # for allowing simulated non-blocking operations
    # (useful for keyboard break)
    RTSP_SOFT_TIMEOUT = 100  # in milliseconds

    def __init__(self, dstport: int, file: str, dstip: str):
        self._video_stream: Union[None, VideoStream] = None
        self._rtp_send_thread: Union[None, Thread] = None
        self._rtp_socket: Union[None, socket.socket] = None
        self._client_address: (str, int) = (dstip, dstport)
        self.file = file

    def setup(self):
        packet =  RTSPPacket.from_request(self.file, self._client_address[1])
        self._setup_rtp(packet.video_file_path)

    def _start_rtp_send_thread(self):
        self._rtp_send_thread = Thread(target=self._handle_video_send)
        self._rtp_send_thread.setDaemon(True)
        self._rtp_send_thread.start()

    def _setup_rtp(self, video_file_path: str):
        print(f"Opening up video stream for file {video_file_path}")
        self._video_stream = VideoStream(video_file_path)
        print('Setting up RTP socket...')
        self._rtp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._start_rtp_send_thread()

    def _send_rtp_packet(self, packet: bytes):
        to_send = packet[:]
        while to_send:
            try:
                self._rtp_socket.sendto(to_send[:self.DEFAULT_CHUNK_SIZE], self._client_address)
            except socket.error as e:
                print(f"failed to send rtp packet: {e}")
                return
            # trim bytes sent
            to_send = to_send[self.DEFAULT_CHUNK_SIZE:]

    def _handle_video_send(self):
        print(f"Sending video to {self._client_address[0]}:{self._client_address[1]}")

        while True:
            if self._video_stream.current_frame_number >= VideoStream.VIDEO_LENGTH-1:  # frames are 0-indexed
                print('Reached end of file.')
                self.server_state = self.STATE.FINISHED
                return
            frame = self._video_stream.get_next_frame()
            frame_number = self._video_stream.current_frame_number
            rtp_packet = RTPPacket(
                payload_type=RTPPacket.TYPE.MJPEG,
                sequence_number=frame_number,
                timestamp=frame_number*self.FRAME_PERIOD,
                payload=frame
            )
            print(f"Sending packet #{frame_number}")
            print('Packet header:')
            rtp_packet.print_header()
            packet = rtp_packet.get_packet()
            self._send_rtp_packet(packet)
            sleep(self.FRAME_PERIOD/1000.)