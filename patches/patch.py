import shutil
import sys
import os
import re
import subprocess

def hb_info(msg):
    level = 'info'
    for line in str(msg).splitlines():
        sys.stdout.write(message(level, line))
        sys.stdout.flush()


def hb_warning(msg):
    level = 'warning'
    for line in str(msg).splitlines():
        sys.stderr.write(message(level, line))
        sys.stderr.flush()


def hb_error(msg):
    level = 'error'
    for line in str(msg).splitlines():
        sys.stderr.write(message(level, line))
        sys.stderr.flush()


def message(level, msg):
    if isinstance(msg, str) and not msg.endswith('\n'):
        msg += '\n'
    return '[OHOS {}] {}'.format(level.upper(), msg)


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args,
                                                                 **kwargs)
        return cls._instances[cls]


class OHOSException(Exception):
    pass


def exec_command(cmd, **kwargs):
    useful_info_pattern = re.compile(r'\[\d+/\d+\].+')
    is_log_filter = kwargs.pop('log_filter', False)

    process = subprocess.Popen(cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               encoding='utf-8',
                               **kwargs)
    for line in iter(process.stdout.readline, ''):
        if is_log_filter:
            info = re.findall(useful_info_pattern, line)
            if len(info):
                hb_info(info[0])
        else:
            hb_info(line)

    process.wait()
    ret_code = process.returncode


if __name__ == '__main__':
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
        root_dir = os.path.join(os.getcwd(), root_dir)
        patch_path = os.path.join(root_dir, "vendor/huawei/ipcamera_v3s/patches/v3s_liteos_a.patch")
        kernel_path = os.path.join(root_dir, "kernel/liteos_a/")
        kconfig_path = os.path.join(kernel_path, "platform/Kconfig")
        need_patch = False
        with open(kconfig_path) as kconfig_f:
            if "v3s" not in kconfig_f.read():
                need_patch = True

        if need_patch:
            cmd = f'patch -p1 < {patch_path}'
            exec_command(cmd, cwd=kernel_path, shell=True)
