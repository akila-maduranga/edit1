import sys
sys.path.insert(0, r'E:\New folder (7)\New folder (9)')
from patcher_core import patch_all
import os

f = open(r'E:\Movies\log.txt', 'w', encoding='utf-8')
def log(msg):
    f.write(msg + '\n')

ok = patch_all(
    r'E:\Movies\video_20260619_163846.mp4',
    r'E:\Movies\test_final.mp4',
    comment='@akila',
    log_func=log,
    method='inflate'
)
f.close()
print('SUCCESS' if ok else 'FAILED')
if os.path.exists(r'E:\Movies\test_final.mp4'):
    print('Size:', os.path.getsize(r'E:\Movies\test_final.mp4'), 'bytes')
