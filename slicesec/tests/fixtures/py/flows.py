import os, subprocess
def run(cmd):
    full = "ls " + cmd
    os.system(full)
def main():
    name = input()
    path = "/tmp/" + name
    run(name)
    with open(path) as f:
        data = f.read()
    subprocess.run(data, shell=True)
