#!/usr/bin/env python3
# sok_super_Agent_UI_UX_v4.3_AutoConnect_Client.py (Tự động tìm SOK Server)
# -*- coding: utf-8 -*-

"""
Một giao diện dòng lệnh duy nhất tích hợp đầy đủ chức năng của Smart Wallet
(P2P, AI Chat, Quản lý Website) và Intelligent Miner (tự động đào nền),
với khả năng tự động tìm và kết nối đến SOK Server tốt nhất.
"""
import os, sys, requests, json, time, logging, random, socket, threading, getpass, base64
from typing import List, Dict, Any, Optional
from decimal import Decimal, getcontext, InvalidOperation
from colorama import Fore, Style, init as colorama_init
from contextlib import contextmanager
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print(Fore.RED + "Lỗi: Thư viện 'cryptography' chưa được cài đặt."); print(Fore.YELLOW + "Vui lòng chạy lệnh: pip install cryptography"); sys.exit(1)

colorama_init(autoreset=True)
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path: sys.path.insert(0, project_root)
try:
    from sok.wallet import Wallet
    from sok.transaction import Transaction
except ImportError as e:
    print(Fore.RED + f"FATAL: Không thể import thư viện 'sok'. Đảm bảo bạn đang chạy file này từ thư mục gốc của dự án. Lỗi: {e}"); sys.exit(1)

# --- CẤU HÌNH ---
DEFAULT_WALLET_FILE = "my_smart_wallet.enc"; LOG_FILE = "sok_super_app.log"; LOCK_PORT = 19999
LIVE_NETWORK_CONFIG_FILE = "live_network_nodes.json"; BOOTSTRAP_CONFIG_FILE = "bootstrap_config.json"
NODE_HEALTH_CHECK_TIMEOUT = 4; MINING_REQUEST_TIMEOUT = 130; MINING_INTERVAL_SECONDS = 120
RETRY_SEARCH_INTERVAL_SECONDS = 30; POST_FAILURE_DELAY_SECONDS = 5; CRITICAL_ERROR_DELAY_SECONDS = 60
TOP_TIER_BLOCK_HEIGHT_TOLERANCE = 1; HEARTBEAT_INTERVAL_SECONDS = 90

STRATEGIC_PAUSE_MIN_SECONDS = 3
STRATEGIC_PAUSE_MAX_SECONDS = 8
NODE_RE_EVALUATION_INTERVAL_SECONDS = 5 * 60

# [THÊM MỚI] URL để tải danh sách SOK Server (Prime Agent)
PRIME_AGENTS_LIST_URL = "https://raw.githubusercontent.com/poybro/sokip/main/federation_peers.json"

logging.basicConfig(level=logging.INFO, format='%(asctime)s [SuperApp] %(message)s', encoding='utf-8', handlers=[logging.FileHandler(LOG_FILE, 'w', encoding='utf-8'), logging.StreamHandler(sys.stdout)])
getcontext().prec = 18
spinner_stop_event = threading.Event()

class UIHelper:
    # ... (Nội dung class UIHelper không thay đổi)
    @staticmethod
    def print_banner():
        print(Fore.MAGENTA + Style.BRIGHT); print("██████╗ ██╗  ██╗██╗  ██╗     ██████╗ ██╗   ██╗██████╗ ██████╗ ██████╗ █████╗ ██████╗  ██████╗"); print("██╔═══╝ ██║ ██╔╝██║ ██╔╝    ██╔═══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝"); print("██████╗ █████╔╝ █████╔╝     ██║   ██║██║   ██║██████╔╝██████╔╝██████╔╝███████║██████╔╝██║     "); print("╚═══██║ ██╔═██╗ ██╔═██╗     ██║   ██║██║   ██║██╔═══╝ ██╔══██╗██╔══██╗██╔══██║██╔══██╗██║     "); print("██████╔╝ ██║  ██╗██║  ██╗    ╚██████╔╝╚██████╔╝██║     ██║  ██║██║  ██║██║  ██║██║  ██║╚██████╗"); print("╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝     ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝"); print(Fore.CYAN + "               >> Siêu Ứng Dụng v4.3 - Tự động Kết nối Server <<"); print(Style.RESET_ALL)
    @staticmethod
    def print_header(title: str): print("\n" + Fore.MAGENTA + "╔" + "═" * (len(title) + 4) + "╗"); print(f"║  {Style.BRIGHT}{title}  ║"); print("╚" + "═" * (len(title) + 4) + "╝" + Style.RESET_ALL)
    @staticmethod
    def print_menu(title: str, options: Dict[str, str]):
        UIHelper.print_header(title)
        for key, value in options.items(): print(f"  {Fore.CYAN}{Style.BRIGHT}{key}{Style.RESET_ALL} - {value}")
        print(Fore.MAGENTA + "─" * 40)
    @staticmethod
    def prompt(message: str = "Chọn một chức năng") -> str: return input(f"{Fore.YELLOW}{message} ❯{Style.RESET_ALL} ").strip()
    @staticmethod
    def message(level: str, text: str):
        levels = {'success': Fore.GREEN + '[✓]', 'error': Fore.RED + '[✗]', 'info': Fore.BLUE + '[i]', 'warning': Fore.YELLOW + '[⚠]'}
        print(f"\n{levels.get(level, '')} {text}{Style.RESET_ALL}")
    @staticmethod
    def press_enter_to_continue(): input(f"\n{Fore.YELLOW}Nhấn [Enter] để quay lại menu...{Style.RESET_ALL}")
    @staticmethod
    def _spin(label):
        spinner_chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']; i = 0
        while not spinner_stop_event.is_set():
            sys.stdout.write(f"\r{Fore.CYAN}{spinner_chars[i % len(spinner_chars)]} {label}{Style.RESET_ALL}"); sys.stdout.flush(); time.sleep(0.08); i += 1
        sys.stdout.write(f"\r{' ' * (len(label) + 5)}\r"); sys.stdout.flush()
    @staticmethod
    @contextmanager
    def spinner(label="Đang xử lý..."):
        spinner_thread = threading.Thread(target=UIHelper._spin, args=(label,), daemon=True)
        spinner_stop_event.clear(); spinner_thread.start()
        try: yield
        finally: spinner_stop_event.set(); spinner_thread.join()
    @staticmethod
    def print_table(headers: List[str], rows: List[List[str]]):
        if not rows: return
        col_widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row): col_widths[i] = max(col_widths[i], len(str(cell)))
        header_line = " │ ".join([f"{header:<{col_widths[i]}}" for i, header in enumerate(headers)]); separator = "─┼─".join(["─" * width for width in col_widths])
        print(Fore.CYAN + header_line); print(Fore.CYAN + separator)
        for row in rows:
            row_line = " │ ".join([f"{str(cell):<{col_widths[i]}}" for i, cell in enumerate(row)])
            print(row_line)

class SokSuperApp:
    def __init__(self):
        UIHelper.print_banner()
        self.wallet = self._load_or_create_wallet()
        
        # [THAY ĐỔI] Tự động tìm server thay vì hỏi người dùng
        self.server_url = self._auto_discover_best_server()
        if not self.server_url:
            UIHelper.message('error', "Không thể tìm thấy SOK Server nào đang hoạt động. Vui lòng thử lại sau.")
            sys.exit(1)
            
        self._check_server_status() # Vẫn kiểm tra lại server đã chọn
        
        self.treasury_address: Optional[str] = None
        self.price_info: Dict[str, Any] = {}
        self._load_initial_data()
        self.miner_status = {"state": "STOPPED", "current_node": "None", "last_log": "Thợ mỏ chưa được khởi động."}
        self.app_is_running = threading.Event()
        self.miner_is_active = threading.Event()
        self.miner_thread: Optional[threading.Thread] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

    # [THÊM MỚI] Hàm tự động tìm SOK Server tốt nhất
    def _auto_discover_best_server(self) -> Optional[str]:
        UIHelper.print_header("TÌM KIẾM SOK SERVER")
        UIHelper.message('info', f"Đang tải danh sách server từ GitHub...")
        try:
            response = requests.get(PRIME_AGENTS_LIST_URL, timeout=10)
            response.raise_for_status()
            config = response.json()
            server_endpoints = config.get("peer_endpoints", [])
            if not server_endpoints:
                UIHelper.message('error', "Danh sách server từ GitHub bị rỗng.")
                return None
        except (requests.RequestException, json.JSONDecodeError) as e:
            UIHelper.message('error', f"Không thể tải danh sách server từ GitHub: {e}")
            return None
            
        UIHelper.message('info', f"Đã tìm thấy {len(server_endpoints)} server. Đang kiểm tra kết nối...")
        
        live_servers = []
        threads = []
        def check_server(url, result_list):
            try:
                start_time = time.time()
                ping_response = requests.get(f"{url}/ping", timeout=3)
                if ping_response.status_code == 200:
                    latency = time.time() - start_time
                    result_list.append({"url": url, "latency": latency})
            except requests.RequestException:
                pass # Bỏ qua server không kết nối được

        for server_url in server_endpoints:
            thread = threading.Thread(target=check_server, args=(server_url, live_servers))
            threads.append(thread)
            thread.start()
        
        for t in threads:
            t.join(3.5)

        if not live_servers:
            return None
        
        # Sắp xếp các server theo độ trễ (latency) thấp nhất
        best_server = sorted(live_servers, key=lambda x: x['latency'])[0]
        return best_server['url']

    # ... (Các hàm còn lại giữ nguyên logic, chỉ cần thay thế hàm khởi tạo)
    # ...
    def _safe_decimal(self, value: Any, default: Decimal = Decimal('0')) -> Decimal:
        if value is None: return default
        try: return Decimal(value)
        except (InvalidOperation, TypeError): return default

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

    def _encrypt_pem(self, pem_data: str, password: str) -> bytes:
        salt = os.urandom(16); key = self._derive_key(password, salt)
        return salt + Fernet(key).encrypt(pem_data.encode('utf-8'))

    def _decrypt_pem(self, encrypted_data: bytes, password: str) -> Optional[str]:
        try:
            salt, token = encrypted_data[:16], encrypted_data[16:]
            key = self._derive_key(password, salt)
            return Fernet(key).decrypt(token).decode('utf-8')
        except (InvalidToken, IndexError, TypeError): return None

    def _load_or_create_wallet(self) -> Wallet:
        UIHelper.print_header("QUẢN LÝ VÍ SOK")
        wallet_file = UIHelper.prompt(f"Nhập tên file ví (mặc định: {DEFAULT_WALLET_FILE})") or DEFAULT_WALLET_FILE
        if os.path.exists(wallet_file):
            if wallet_file.endswith('.pem'):
                with open(wallet_file, 'r', encoding='utf-8') as f: return Wallet(private_key_pem=f.read())
            elif wallet_file.endswith('.enc'):
                password = getpass.getpass("Nhập mật khẩu để giải mã ví: ")
                with UIHelper.spinner("Đang giải mã..."):
                    with open(wallet_file, 'rb') as f: pem_data = self._decrypt_pem(f.read(), password)
                if pem_data:
                    UIHelper.message('success', "Giải mã ví thành công."); return Wallet(private_key_pem=pem_data)
                else: UIHelper.message('error', "Mật khẩu sai hoặc file ví bị lỗi."); sys.exit(1)
            else: UIHelper.message('error', f"Định dạng file '{wallet_file}' không được hỗ trợ."); sys.exit(1)
        UIHelper.message('warning', f"Không tìm thấy tệp ví '{wallet_file}'.")
        if UIHelper.prompt("Tạo ví mới? (yes/no)").lower() != 'yes': sys.exit(0)
        wallet = Wallet(); pem_data = wallet.get_private_key_pem()
        if UIHelper.prompt("Bạn có muốn mã hóa ví mới bằng mật khẩu không? (yes/no)").lower() == 'yes':
            wallet_file += '.enc' if not wallet_file.endswith('.enc') else ''
            while True:
                password = getpass.getpass("Nhập mật khẩu mới cho ví: ")
                if password and password == getpass.getpass("Xác nhận mật khẩu: "): break
                UIHelper.message('error', "Mật khẩu không khớp hoặc để trống.")
            with open(wallet_file, 'wb') as f: f.write(self._encrypt_pem(pem_data, password))
            UIHelper.message('success', f"Đã tạo và mã hóa ví, lưu tại '{wallet_file}'.")
        else:
            wallet_file += '.pem' if not wallet_file.endswith('.pem') else ''
            with open(wallet_file, 'w', encoding='utf-8') as f: f.write(pem_data)
            UIHelper.message('success', f"Đã tạo ví không mã hóa, lưu tại '{wallet_file}'.")
        UIHelper.print_header("TẠO VÍ THÀNH CÔNG"); print(f"{Fore.CYAN}ĐỊA CHỈ VÍ CỦA BẠN: {Style.BRIGHT}{wallet.get_address()}"); print(Fore.YELLOW + Style.BRIGHT + "QUAN TRỌNG: Hãy sao lưu file ví và ghi nhớ mật khẩu thật cẩn thận!")
        return wallet

    def _make_api_request(self, method: str, endpoint: str, **kwargs) -> Any:
        url = f"{self.server_url}{endpoint}"; kwargs.setdefault('timeout', 15)
        try:
            with UIHelper.spinner("Đang kết nối với server..."):
                response = requests.request(method.upper(), url, **kwargs)
            if response.status_code >= 400:
                try:
                    error_details = response.json().get('error', response.text)
                except json.JSONDecodeError:
                    error_details = response.text
                UIHelper.message('error', f"Server lỗi ({response.status_code}): {error_details}");
                return None
            return response.json()
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            UIHelper.message('error', f"Lỗi giao tiếp mạng: {e}"); return None

    def _check_server_status(self):
        UIHelper.message('info', f"Đang kiểm tra kết nối tới Server tại {self.server_url}...")
        try:
            assert requests.get(f"{self.server_url}/ping", timeout=3).status_code == 200
            UIHelper.message('success', "Kết nối thành công.")
        except Exception:
            UIHelper.message('error', f"Không thể kết nối đến SOK Server. Vui lòng kiểm tra IP và đảm bảo server đang chạy."); sys.exit(1)

    def _load_initial_data(self):
        UIHelper.message('info', "Đang tải cấu hình ban đầu từ server...")
        payment_data = self._make_api_request('GET', '/api/v1/payment_info')
        if payment_data: self.treasury_address = payment_data.get('treasury_address'); self.price_info = payment_data

    def _create_signed_request(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        message_data.setdefault('address', self.wallet.get_address())
        message_data.setdefault('timestamp', int(time.time()))
        message_to_sign = json.dumps(message_data, sort_keys=True, separators=(',', ':'))
        signature = Transaction.sign_message(self.wallet.get_private_key_pem(), message_to_sign)
        return {'message_data': message_data, 'signature': signature, 'public_key_pem': self.wallet.get_public_key_pem()}

    def _run_menu_loop(self, title: str, options: Dict, actions: Dict):
        while self.app_is_running.is_set():
            UIHelper.print_menu(title, options); choice = UIHelper.prompt()
            action = actions.get(choice)
            if action:
                try: action()
                except Exception as e:
                    logging.critical(f"Lỗi nghiêm trọng khi chạy '{action.__name__}': {e}", exc_info=True)
                    UIHelper.message('error', "Đã xảy ra lỗi không mong muốn. Vui lòng kiểm tra log để biết chi tiết.")
            elif choice == '0': break
            else: UIHelper.message('error', "Lựa chọn không hợp lệ.")

    def _p2p_menu(self): self._run_menu_loop("GIAO DỊCH P2P", {'1': "Xem lệnh bán", '2': "Giao dịch của tôi", '3': "Tạo lệnh bán", '4': "Mua SOK", '5': "[Bán] Xác nhận thanh toán", '6': "[Bán] Hủy lệnh", '0': "Quay lại"}, {'1': self._list_open_p2p_orders, '2': self._list_my_p2p_orders, '3': self._create_p2p_order, '4': self._accept_p2p_order, '5': self._confirm_p2p_payment, '6': self._cancel_p2p_order})
    def _website_menu(self): self._run_menu_loop("QUẢN LÝ WEBSITE", {'1': "Liệt kê Website", '2': "Thêm Website", '3': "Xóa Website", '4': "Nạp SOK mua lượt xem", '0': "Quay lại"}, {'1': self._list_my_websites, '2': self._add_website, '3': self._remove_website, '4': self._fund_websites})
    def _utilities_menu(self): self._run_menu_loop("TIỆN ÍCH", {'1': "Gửi SOK", '2': "Kiểm tra ví khác", '3': "Hiển thị ví của tôi", '0': "Quay lại"}, {'1': self.send_transaction, '2': self._check_other_balance, '3': self._show_my_wallet})
    def _miner_control_menu(self): self._run_menu_loop("CHẾ ĐỘ THỢ MỎ", {'1': "Xem trạng thái", '2': "Bắt đầu / Tiếp tục đào", '3': "Tạm dừng đào", '4': "Buộc tìm Node mới", '0': "Quay lại"}, {'1': self._show_miner_status, '2': self._start_miner, '3': self._stop_miner, '4': self._force_find_new_node})
    
    def refresh_dashboard(self):
        profile_data = self._make_api_request('GET', f"/api/v1/user_profile/{self.wallet.get_address()}")
        stats_data = self._make_api_request('GET', '/api/v1/dashboard_stats')
        UIHelper.print_header("BẢNG ĐIỀU KHIỂN VÍ SOK")
        print(Fore.WHITE + "╔═══════════════════════ PROFILE CÁ NHÂN ════════════════════════╗")
        if profile_data:
            print(f"║ {Fore.CYAN}Số dư ví:       {Style.BRIGHT}{self._safe_decimal(profile_data.get('sok_balance')):>18.8f} SOK{Style.RESET_ALL}            ║")
            print(f"║ {Fore.CYAN}Số website:      {Style.BRIGHT}{profile_data.get('website_count', 0):>2} trang{Style.RESET_ALL}                              ║")
        else:
            print(f"║ {Fore.RED}Không thể tải thông tin cá nhân. Vui lòng kiểm tra lại.{Style.RESET_ALL}        ║")
        print("╠═══════════════════════ TRẠNG THÁI MẠNG LƯỚI ═══════════════════════╣")
        if stats_data:
            status = stats_data.get('status', 'Connecting...')
            status_color = Fore.GREEN if 'Online' in status else Fore.RED
            print(f"║ {Fore.WHITE}Trạng thái mạng: {status_color}{status:<10}{Style.RESET_ALL}                                       ║")
            print(f"║ {Fore.WHITE}Chiều cao khối:  {stats_data.get('blockchain_height', 'N/A'):<10}{Style.RESET_ALL}                                       ║")
            print(f"║ {Fore.WHITE}Worker hoạt động:{stats_data.get('active_workers', 'N/A'):<10}{Style.RESET_ALL}                                       ║")
        else:
             print(f"║ {Fore.RED}Không thể tải trạng thái mạng lưới.{Style.RESET_ALL}                         ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        
    def _list_open_p2p_orders(self):
        UIHelper.print_header("THỊ TRƯỜNG P2P (LỆNH ĐANG MỞ)")
        orders = self._make_api_request('GET', '/api/v1/p2p/orders/list')
        if not orders:
            UIHelper.message('info', "Hiện không có lệnh bán nào trên thị trường.")
        else:
            headers = ["ID Lệnh", "Số lượng SOK", "Chi tiết Thanh toán"]
            rows = [[o.get('id', 'N/A'), f"{self._safe_decimal(o.get('sok_amount')):.4f}", o.get('fiat_details', 'N/A')] for o in orders]
            UIHelper.print_table(headers, rows)
        UIHelper.press_enter_to_continue()
    
    def _list_my_p2p_orders(self):
        UIHelper.print_header("LỊCH SỬ GIAO DỊCH P2P CỦA BẠN")
        orders = self._make_api_request('GET', f"/api/v1/p2p/my_orders?address={self.wallet.get_address()}")
        if not orders: UIHelper.message('info', "Bạn chưa có giao dịch P2P nào.")
        else:
            headers = ["ID Lệnh", "Vai trò", "Số lượng SOK", "Trạng thái", "Chi tiết Thanh toán"]
            rows = []
            for o in orders:
                role = f"{Fore.RED}BÁN{Style.RESET_ALL}" if o.get('seller_address') == self.wallet.get_address() else f"{Fore.GREEN}MUA{Style.RESET_ALL}"
                amount = f"{self._safe_decimal(o.get('sok_amount')):.4f}"
                rows.append([o.get('id', 'N/A'), role, amount, o.get('status', 'N/A'), o.get('fiat_details', 'N/A')])
            UIHelper.print_table(headers, rows)
        UIHelper.press_enter_to_continue()
        
    def _create_p2p_order(self):
        UIHelper.print_header("TẠO LỆNH BÁN SOK"); amount = UIHelper.prompt("Số lượng SOK bán"); fiat = UIHelper.prompt("Thông tin nhận tiền (Ví dụ: Tên, STK, Ngân hàng)")
        if not self._safe_decimal(amount) > 0 or not fiat: UIHelper.message('error', "Thông tin không hợp lệ hoặc để trống."); return
        data = self._make_api_request('POST', '/api/v1/p2p/orders/create', json={"seller_address": self.wallet.get_address(), "sok_amount": amount, "fiat_details": fiat});
        if data: UIHelper.message('success', "Tạo lệnh thành công!"); UIHelper.message('warning', f"GỬI {amount} SOK đến ví ký quỹ: {data.get('escrow_address')}")

    def _accept_p2p_order(self):
        order_id = UIHelper.prompt("Nhập ID lệnh muốn mua");
        if not order_id: UIHelper.message('error', "ID không được để trống."); return
        data = self._make_api_request('POST', f"/api/v1/p2p/orders/{order_id}/accept", json={"buyer_address": self.wallet.get_address()});
        if data: UIHelper.message('success', data.get('message')); UIHelper.message('info', "Vui lòng chuyển khoản và chờ người bán xác nhận.")

    def _confirm_p2p_payment(self):
        order_id = UIHelper.prompt("Nhập ID lệnh đã nhận thanh toán")
        if not order_id: UIHelper.message('error', "ID không được để trống."); return
        UIHelper.message('info', "Đang tạo chữ ký số...")
        message_data = {"action": "p2p_confirm", "order_id": order_id}
        signed_payload = self._create_signed_request(message_data)
        response_data = self._make_api_request('POST', f"/api/v1/p2p/orders/{order_id}/confirm", json=signed_payload)
        if response_data: UIHelper.message('success', response_data.get('message'))

    def _cancel_p2p_order(self):
        order_id = UIHelper.prompt("Nhập ID lệnh muốn hủy")
        if not order_id: UIHelper.message('error', "ID không được để trống."); return
        UIHelper.message('info', "Đang tạo chữ ký số...")
        message_data = {"action": "p2p_cancel", "order_id": order_id}
        signed_payload = self._create_signed_request(message_data)
        response_data = self._make_api_request('POST', f"/api/v1/p2p/orders/{order_id}/cancel", json=signed_payload)
        if response_data: UIHelper.message('success', response_data.get('message'))

    def _list_my_websites(self):
        UIHelper.print_header("DANH SÁCH WEBSITE CỦA BẠN")
        websites = self._make_api_request('GET', f'/api/v1/websites/list?owner={self.wallet.get_address()}')
        if not websites: UIHelper.message('info', "Bạn chưa thêm website nào.")
        else:
            headers = ["URL", "Lượt xem đã nạp", "Lượt xem hoàn thành"]
            rows = []
            for site in websites:
                info = site.get('info', {})
                rows.append([site.get('url', 'N/A'), str(info.get('views_funded', '0')), str(info.get('views_completed', '0'))])
            UIHelper.print_table(headers, rows)
        UIHelper.press_enter_to_continue()

    def _add_website(self):
        UIHelper.print_header("THÊM WEBSITE MỚI"); url = UIHelper.prompt("Nhập URL đầy đủ (ví dụ: https://example.com)");
        if not url: UIHelper.message('error', "URL không được để trống."); return
        response = self._make_api_request('POST', '/api/v1/websites/add', json={"url": url, "owner_pk_pem": self.wallet.get_public_key_pem()});
        if response: UIHelper.message('success', response.get('message', "Thêm thành công!"))

    def _remove_website(self):
        UIHelper.print_header("XÓA WEBSITE"); self._list_my_websites(); print(""); url = UIHelper.prompt("Nhập chính xác URL của website muốn xóa");
        if not url: UIHelper.message('error', "URL không được để trống."); return
        if UIHelper.prompt(f"Bạn có chắc muốn xóa '{url}'? (yes/no)").lower() != 'yes': UIHelper.message('info', "Đã hủy."); return
        response = self._make_api_request('POST', '/api/v1/websites/remove', json={"url": url, "owner_address": self.wallet.get_address()});
        if response: UIHelper.message('success', response.get('message', "Xóa thành công!"))

    def _fund_websites(self):
        UIHelper.print_header("NẠP SOK MUA LƯỢT XEM");
        if not self.treasury_address: UIHelper.message('error', "Không thể lấy địa chỉ kho bạc."); return
        UIHelper.message('info', "SOK bạn gửi sẽ được tự động đổi thành lượt xem cho website của bạn."); print("-" * 40)
        print(f"  {Fore.CYAN}Địa chỉ Kho bạc: {Style.BRIGHT}{self.treasury_address}{Style.RESET_ALL}");
        print(f"  {Fore.CYAN}Tỷ giá: {Style.BRIGHT}{self.price_info.get('price_per_100_views', 'N/A')} SOK / 100 lượt xem"); print("-" * 40)
        self.send_transaction(prefilled_recipient=self.treasury_address)

    def _chat_with_ai(self):
        UIHelper.print_header("TRÒ CHUYỆN VỚI TRỢ LÝ AI"); print("     (Nhập 'exit' hoặc 'quit' để thoát)");
        while True:
            query = input(f"\n{Fore.CYAN}Bạn ❯{Style.RESET_ALL} ").strip()
            if query.lower() in ['exit', 'quit']: break;
            if not query: continue
            data = self._make_api_request('POST', '/api/v1/ai/chat', json={"query": query, "address": self.wallet.get_address()});
            print(f"{Fore.GREEN}AI ❯{Style.RESET_ALL} {data.get('reply') if data else 'Lỗi giao tiếp với AI.'}")

    def send_transaction(self, prefilled_recipient: Optional[str] = None):
        recipient = prefilled_recipient or UIHelper.prompt("Nhập địa chỉ nhận");
        if not recipient: UIHelper.message('error', "Địa chỉ không được để trống."); return
        amount_str = UIHelper.prompt(f"Số SOK muốn gửi đến {recipient[:15]}...")
        if not self._safe_decimal(amount_str) > 0: UIHelper.message('error', "Số tiền không hợp lệ."); return
        UIHelper.message('info', "Đang gửi giao dịch...");
        data = self._make_api_request('POST', '/api/direct_fund', json={"private_key_pem": self.wallet.get_private_key_pem(), "recipient_address": recipient, "amount": amount_str});
        if data: UIHelper.message('success', f"Server: {data.get('message')}")

    def _check_other_balance(self):
        addr = UIHelper.prompt("Nhập địa chỉ ví cần kiểm tra");
        if not addr: UIHelper.message('error', "Địa chỉ không được để trống."); return
        data = self._make_api_request('GET', f"/api/get_balance/{addr}");
        if data: UIHelper.message('success', f"Số dư của ví {addr[:10]}...: {self._safe_decimal(data.get('balance')):.8f} SOK")

    def _show_my_wallet(self):
        UIHelper.print_header("ĐỊA CHỈ VÍ CỦA BẠN")
        print(f"{Style.BRIGHT} >> {self.wallet.get_address()} << ")
        UIHelper.press_enter_to_continue()
    
    def _show_guide(self):
        UIHelper.print_header("HƯỚNG DẪN THAM GIA MẠNG LƯỚI SOK")
        print(f"{Fore.WHITE}Bất kỳ ai cũng có thể đóng góp sức mạnh xử lý (CPU) cho mạng lưới và nhận phần thưởng SOK.")
        
        print("\n" + Fore.CYAN + Style.BRIGHT + "1. Tải và Chia sẻ Client Miner:")
        print(f"{Fore.WHITE}   - Bạn đang sử dụng chính Client Miner này (`{os.path.basename(__file__)}`).")
        print(f"{Fore.WHITE}   - Bạn có thể chia sẻ tệp này cho người khác để họ cùng tham gia.")
        
        print("\n" + Fore.CYAN + Style.BRIGHT + "2. Thiết lập Ví:")
        print(f"{Fore.WHITE}   - Khi khởi động ứng dụng lần đầu, bạn sẽ được hướng dẫn tạo một ví mới hoặc mở ví đã có.")
        print(f"{Fore.WHITE}   - Ví của bạn sẽ được lưu (mã hóa hoặc không) vào một tệp (ví dụ: `my_smart_wallet.enc`).")
        print(f"{Fore.RED + Style.BRIGHT}   - CỰC KỲ QUAN TRỌNG: Hãy sao lưu tệp ví và ghi nhớ mật khẩu (nếu có) thật cẩn thận.")
        
        print("\n" + Fore.CYAN + Style.BRIGHT + "3. Chạy tiến trình:")
        print(f"{Fore.WHITE}   - Mở terminal/command prompt.")
        print(f"{Fore.WHITE}   - Chạy lệnh: {Style.BRIGHT}python {os.path.basename(__file__)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}   - Ứng dụng sẽ tự động tìm SOK Server tốt nhất để kết nối.")
        print(f"{Fore.WHITE}   - Sau đó, vào menu '{Fore.YELLOW}Chế độ Thợ mỏ{Fore.WHITE}' và chọn '{Fore.GREEN}Bắt đầu / Tiếp tục đào{Fore.WHITE}' để khai thác.")
        
        UIHelper.press_enter_to_continue()

    def _show_miner_status(self):
        UIHelper.print_header("TRẠNG THÁI THỢ MỎ"); print(f"  - Trạng thái : {self.miner_status['state']}\n  - Node hiện tại: {self.miner_status['current_node']}\n  - Log cuối   : {self.miner_status['last_log']}")
        UIHelper.press_enter_to_continue()

    def _start_miner(self):
        if not self.miner_is_active.is_set(): UIHelper.message('success', "Đã gửi lệnh BẮT ĐẦU."); self.miner_is_active.set()
        else: UIHelper.message('info', "Thợ mỏ đã đang chạy.")

    def _stop_miner(self):
        if self.miner_is_active.is_set(): UIHelper.message('warning', "Đã gửi lệnh TẠM DỪNG."); self.miner_is_active.clear()
        else: UIHelper.message('info', "Thợ mỏ đã dừng từ trước.")

    def _force_find_new_node(self):
        UIHelper.message('info', "Đã gửi yêu cầu tìm node mới...")
        UIHelper.message('warning', "Thợ mỏ sẽ bắt đầu tìm kiếm ở chu kỳ tiếp theo (sau khi hoàn thành tác vụ hiện tại).")
        self.miner_status['current_node'] = None
    
    def _miner_log(self, state: str, message: str):
        state_colors = {
            "PAUSED": Fore.BLUE, "SEARCHING": Fore.CYAN, "EVALUATING": Fore.CYAN,
            "NODE_SWITCHED": Fore.GREEN + Style.BRIGHT, "MINING": Fore.YELLOW,
            "SUCCESS": Fore.GREEN + Style.BRIGHT, "CONFLICT": Fore.MAGENTA,
            "TIMEOUT": Fore.MAGENTA, "FAILED": Fore.RED,
            "CONNECTION_ERROR": Fore.RED, "CRITICAL": Fore.RED + Style.BRIGHT
        }
        color = state_colors.get(state, Fore.WHITE)
        self.miner_status.update({"state": state, "last_log": message})
        colored_log_message = f"[{color}{state:<16}{Style.RESET_ALL}] {message}"
        logging.info(colored_log_message)

    def _miner_load_all_known_nodes(self) -> List[str]:
        nodes = set()
        for file in [LIVE_NETWORK_CONFIG_FILE, BOOTSTRAP_CONFIG_FILE]:
            # [THAY ĐỔI] Sử dụng hàm helper mới để tải config
            config_data = self._load_config_from_github_or_local(file)
            if not config_data: continue
            try:
                if "active_nodes" in config_data and isinstance(config_data["active_nodes"], list): nodes.update(config_data["active_nodes"])
                if "trusted_bootstrap_peers" in config_data and isinstance(config_data["trusted_bootstrap_peers"], dict):
                    peer_urls = [peer.get('last_known_address') for peer in config_data["trusted_bootstrap_peers"].values() if peer.get('last_known_address')]
                    nodes.update(peer_urls)
            except Exception as e: logging.error(f"Lỗi xử lý dữ liệu từ file node '{file}': {e}")
        return list(filter(None, nodes))
    
    # [THÊM MỚI] Hàm helper để tải config cho miner, tránh lặp code
    def _load_config_from_github_or_local(self, filename: str) -> Optional[Dict]:
        try:
            url = "https://raw.githubusercontent.com/poybro/sokip/main/" + filename
            response = requests.get(url, timeout=5)
            if response.ok:
                return response.json()
        except requests.RequestException:
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except: pass
        return None

    def _miner_find_best_node(self) -> Optional[Dict]:
        known_nodes = self._miner_load_all_known_nodes()
        if not known_nodes: self._miner_log("FAILED", "Không có node nào trong cấu hình."); return None
        healthy_nodes = []
        threads = []
        
        def check_node(url, result_list):
            try:
                stats = requests.get(f'{url}/chain/stats', timeout=NODE_HEALTH_CHECK_TIMEOUT).json()
                result_list.append({"url": url, "height": stats.get('block_height', -1)})
            except:
                pass

        for url in known_nodes:
            thread = threading.Thread(target=check_node, args=(url, healthy_nodes))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(NODE_HEALTH_CHECK_TIMEOUT)

        if not healthy_nodes: self._miner_log("FAILED", "Không tìm thấy node nào hoạt động."); return None
        
        max_height = max(n['height'] for n in healthy_nodes)
        top_tier = [n for n in healthy_nodes if n['height'] >= max_height - TOP_TIER_BLOCK_HEIGHT_TOLERANCE]
        
        if not top_tier:
             top_tier = sorted(healthy_nodes, key=lambda x: x['height'], reverse=True)

        chosen_node = random.choice(top_tier)
        return chosen_node
        
    def _miner_main_loop(self):
        last_node_re_evaluation_time = 0

        while self.app_is_running.is_set():
            if not self.miner_is_active.is_set():
                if self.miner_status['state'] != "PAUSED":
                    self._miner_log("PAUSED", "Thợ mỏ đang tạm dừng. Chờ lệnh từ người dùng.")
                time.sleep(5)
                continue

            try:
                node_is_stale = (time.time() - last_node_re_evaluation_time) > NODE_RE_EVALUATION_INTERVAL_SECONDS
                if not self.miner_status.get('current_node') or node_is_stale:
                    if node_is_stale: self._miner_log("EVALUATING", "Đã đến lúc đánh giá lại hiệu quả của node hiện tại...")
                    else: self._miner_log("SEARCHING", "Bắt đầu quét mạng lưới tìm node tốt nhất...")
                    
                    target_node_info = self._miner_find_best_node()
                    if not target_node_info:
                        self._miner_log("FAILED", f"Không tìm thấy node nào phù hợp. Thử lại sau {RETRY_SEARCH_INTERVAL_SECONDS}s.")
                        time.sleep(RETRY_SEARCH_INTERVAL_SECONDS)
                        continue
                    
                    self.miner_status['current_node'] = target_node_info['url']
                    last_node_re_evaluation_time = time.time()
                    self._miner_log("NODE_SWITCHED", f"Đã chọn node tối ưu: {self.miner_status['current_node']} (Block: {target_node_info.get('height')})")

                node_url = self.miner_status['current_node']
                if not node_url: time.sleep(1); continue

                self._miner_log("MINING", f"Gửi yêu cầu khai thác tới {node_url}...")
                response = requests.get(f"{node_url}/mine", params={'miner_address': self.wallet.get_address()}, timeout=MINING_REQUEST_TIMEOUT)

                if response.status_code == 200:
                    block_index = response.json().get('block', {}).get('index', '?')
                    self._miner_log("SUCCESS", f"THÀNH CÔNG! Đã đào Khối #{block_index}. Chờ chu kỳ tiếp theo.")
                    time.sleep(MINING_INTERVAL_SECONDS)
                elif response.status_code == 409:
                    pause_duration = random.uniform(STRATEGIC_PAUSE_MIN_SECONDS, STRATEGIC_PAUSE_MAX_SECONDS)
                    self._miner_log("CONFLICT", f"Cạnh tranh! Node khác đã tìm thấy khối. Tạm dừng chiến lược {pause_duration:.1f}s.")
                    self.miner_status['current_node'] = None
                    time.sleep(pause_duration)
                else:
                    self._miner_log("FAILED", f"Node {node_url} từ chối: {response.status_code} - {response.text[:80]}")
                    self.miner_status['current_node'] = None
                    time.sleep(POST_FAILURE_DELAY_SECONDS)

            except requests.exceptions.ReadTimeout:
                pause_duration = random.uniform(STRATEGIC_PAUSE_MIN_SECONDS, STRATEGIC_PAUSE_MAX_SECONDS)
                self._miner_log("TIMEOUT", f"Hết thời gian chờ. Mạng có thể đang bận. Tạm dừng chiến lược {pause_duration:.1f}s.")
                self.miner_status['current_node'] = None
                time.sleep(pause_duration)
            except requests.exceptions.RequestException as e:
                self._miner_log("CONNECTION_ERROR", f"Mất kết nối tới node. Lỗi: {str(e)[:80]}")
                self.miner_status['current_node'] = None
                time.sleep(POST_FAILURE_DELAY_SECONDS)
            except Exception as e:
                self._miner_log("CRITICAL", f"Lỗi nghiêm trọng trong vòng lặp đào: {e}")
                self.miner_status['current_node'] = None
                time.sleep(CRITICAL_ERROR_DELAY_SECONDS)

    def _heartbeat_loop(self):
        while self.app_is_running.is_set():
            if self.miner_is_active.is_set():
                try: 
                    requests.post(f"{self.server_url}/heartbeat", json={"worker_address": self.wallet.get_address(), "type": "miner", "status": self.miner_status['state']}, timeout=5)
                except: 
                    logging.warning("Không thể gửi heartbeat.")
            time.sleep(HEARTBEAT_INTERVAL_SECONDS)


    def run(self):
        self.app_is_running.set()
        self.miner_thread = threading.Thread(target=self._miner_main_loop, daemon=True, name="MinerThread")
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True, name="HeartbeatThread")
        self.miner_thread.start(); self.heartbeat_thread.start()
        UIHelper.message('info', "Luồng thợ mỏ và heartbeat đã khởi động ở chế độ nền.")
        self.refresh_dashboard()
        
        main_menu = {'1': "Bảng điều khiển", '2': "Giao dịch P2P", '3': "Quản lý Website", '4': "Chế độ Thợ mỏ", '5': "Tiện ích", '6': "Trò chuyện AI", '7': "Hướng dẫn sử dụng", '0': "Thoát"}
        main_actions = {'1': self.refresh_dashboard, '2': self._p2p_menu, '3': self._website_menu, '4': self._miner_control_menu, '5': self._utilities_menu, '6': self._chat_with_ai, '7': self._show_guide}
        
        self._run_menu_loop("SOK SUPER APP - MENU CHÍNH", main_menu, main_actions)

        self.app_is_running.clear()
        self.stop_event.set()
        UIHelper.message('info', "Đang tắt ứng dụng...")
        print(f"{Fore.CYAN}Tạm biệt và hẹn gặp lại!")

def try_acquire_port_lock(port: int) -> Optional[socket.socket]:
    try:
        lock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lock_socket.bind(("127.0.0.1", port))
        return lock_socket
    except socket.error:
        return None

if __name__ == "__main__":
    lock = try_acquire_port_lock(LOCK_PORT)
    if lock:
        logging.info(f"Đã chiếm giữ khóa trên cổng {LOCK_PORT}.")
        app = None
        try:
            app = SokSuperApp()
            app.run()
        except KeyboardInterrupt:
            print("\nĐã nhận tín hiệu dừng từ người dùng.")
        except Exception as e:
            logging.critical(f"Lỗi không xác định ở luồng chính: {e}", exc_info=True)
        finally:
            if app:
                app.app_is_running.clear()
                app.stop_event.set()
            logging.info("Đang giải phóng khóa.")
            lock.close()
    else:
        logging.error(f"LỖI: Một instance của Super App đã đang chạy (Không thể chiếm giữ cổng {LOCK_PORT})")
        sys.exit(1)
