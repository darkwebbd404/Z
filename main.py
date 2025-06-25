import subprocess
import time

while True:
    # Chạy file Python khác (ví dụ: other_file.py)
    process = subprocess.run(['python', 'app.py'])

    # Nếu file kết thúc, in ra thông báo và chạy lại sau 1 giây
    print("app.py đã kết thúc, sẽ chạy lại sau 1 giây...")
    time.sleep(0)