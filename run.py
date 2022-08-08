import frida
import sys
from loguru import logger
import pprint
import binascii

pp = pprint.PrettyPrinter(width=120)

def on_message(message, data):
    # logger.info('message type: %s' % message['type'])
    t = message['type']
    if t == 'error':
        logger.warning(pp.pformat(message))
    elif t == 'send':
        logger.info(pp.pformat(message['payload']))
    else:
        logger.info('unknown message type: %s' % message.keys())
    
    if data:
        # with open('out.bin', 'wb') as f:
        #     f.write(data)
        logger.info(binascii.hexlify(data))

def handle_cmd(cmd, api):
    cmd = cmd.split()
    if not cmd:
        return
    elif cmd[0] == 'settime':
        api.set_time(float(cmd[1]))
    elif cmd[0] == 'resethint':
        api.reset_hint()
    elif cmd[0] == 'getsets':
        api.get_active_sets()
    elif cmd[0] == 'click':
        api.click(int(cmd[1]), int(cmd[2]))
    elif cmd[0] == 'solve':
        api.solve()
    elif cmd[0] == 'solveall':
        api.solve_all()
    elif cmd[0] == 'stalk':
        api.stalk()
    elif cmd[0] == 'stalkinterval':
        api.stalkinterval(int(cmd[1]), int(cmd[2]))
    elif cmd[0] == 'unstalk':
        api.unstalk()
    elif cmd[0] == 'stat':
        api.stat()
    # elif cmd[0] == 'togglefullscreen':
    #     api.toggle_fullscreen()

def main(target_process):
    device = frida.get_local_device()

    try:
        pid = int(target_process)
        session = device.attach(pid)
    except ValueError:
        pid = device.spawn(target_process)
        logger.info('spawned app with pid %d' % pid)
        session = device.attach(pid)

    # this directly calls the given entrypoint, not what we want
    # device.inject_library_file(pid, "./custom-blitter/stretch.dll", "entry0", "test")
    
    with open('mysterypi.js') as f:
        script = session.create_script(f.read())

    script.on('message', on_message)
    script.load()

    api = script.exports

    device.resume(pid)
    
    print("[!] Ctrl+Z on Windows/cmd.exe to detach.\n\n")
    try:
        while True:
            handle_cmd(input(), api)
    except KeyboardInterrupt:
        logger.info('exiting.')
    except Exception as e:
        logger.error('exception: %s' % e)

    # session.detach()
    device.kill(pid)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <process name or PID>" % __file__)
        sys.exit(1)

    main(sys.argv[1])