import numpy as np
import asyncio
import time

def pack_time():
    s = '{}'.format(time.time())
    s = bytes(s, 'utf8')
    s = s.ljust(32, b'\x00') + b'\x17'
    return s.ljust(497, b'\x00') + b'\n'

def unpack_time(data):
    if len(data) != 498:
        return None
    if data[32] != 0x17 or data[-1] != 0xa:
        return None
    data = str(data[:32].rstrip(b'\x00'), 'utf8')
    return time.time() - float(data)

async def stream(stdout, callback):
    while True:
        line = await stdout.read(498)
        if line:
            await callback(line)
        else:
            break

start = 0
nb_target = 2500
async def load(stdin):
    for i in range(nb_target):
        current = time.time() - start
        delta = (i + 1) * (1 / 250) - current
        if delta > 0:
            await asyncio.sleep(delta)
        stdin.write(pack_time())

async def connect(callback):
    process = await asyncio.create_subprocess_exec(
                'nc', '-x', '127.0.0.1:9008', '127.0.0.1', '12003',
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)

    global start
    start = time.time()
    asyncio.ensure_future(stream(process.stdout, callback))
    await load(process.stdin)
    end = time.time()

    while width < nb_target * 498:
        await asyncio.sleep(0)
    process.kill()

    await process.wait()
    return end - start

width = 0
samples = []
async def handler(line):
    if line is None:
        stdin.write(pack_time())

    global width
    width += len(line)

    last = unpack_time(line)
    if last is not None:
        samples.append(last)

async def main():
    a = await connect(handler)
    b = await connect(handler)
    c = await connect(handler)

    print(len(samples), np.sum(samples) / len(samples), np.std(samples))
    print(3, (a + b + c) / 3, np.std([a, b, c]))

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
loop.close()
