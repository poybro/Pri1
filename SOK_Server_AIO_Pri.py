#!/usr/bin/env python3
# SOK_Server_All_In_One - v14.2_Full_Fix.py (Bản sửa lỗi đầy đủ, ổn định)
# -*- coding: utf-8 -*-

import os, sys, time, requests, json, threading, logging, socket, random, uuid, math, base64, subprocess, hmac, hashlib
from functools import wraps
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS
from queue import Queue, Empty
from waitress import serve
from typing import List, Dict, Optional, Deque
from decimal import Decimal, getcontext
from colorama import Fore, Style, init as colorama_init
import plotly.graph_objects as go
from datetime import datetime
from cryptography.fernet import Fernet
from getpass import getpass 
from collections import deque
try:
    import google.generativeai as genai
except ImportError:
    genai = None

# --- CẤU HÌNH & THIẾT LẬP ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") 
getcontext().prec = 50 
project_root = os.path.abspath(os.path.dirname(__file__))
if os.path.join(project_root, 'sok') not in sys.path: sys.path.insert(0, project_root)
try:
    from sok.wallet import Wallet, get_address_from_public_key_pem, verify_signature
    from sok.transaction import Transaction
    from sok.utils import hash_data
except ImportError as e:
    with open("SERVER_CRITICAL_ERROR.log", "w", encoding='utf-8') as f: f.write(f"Timestamp: {time.ctime()}\nKhông thể import 'sok': {e}\nSys.path: {sys.path}")
    sys.exit(1)

# --- CẤU HÌNH CHUNG ---
PRIME_WALLET_FILE = "prime_agent_wallet.pem"; STATE_FILE = "prime_agent_state.json"; SERVER_PORT = 9000
VALID_ACTIVATION_KEY = "SOK@10" 
P2P_PAYMENT_WINDOW_SECONDS = 1800
P2P_FEE_PERCENT = Decimal('0.5'); PRICE_PER_100_VIEWS = Decimal('1.0'); PLATFORM_FEE_PERCENT = Decimal('20.0'); PRICE_PER_VIEW = PRICE_PER_100_VIEWS / 100; REWARD_AMOUNT = PRICE_PER_VIEW * (1 - PLATFORM_FEE_PERCENT / 100)
ECON_DATA_FILE = "sok_econ_data_v10.json"; ECON_CHART_FILE = os.path.join("static", "sok_valuation_chart.html"); ECON_ANALYSIS_INTERVAL = 300; ECON_INITIAL_TREASURY_USD = Decimal('10000.0'); ECON_INITIAL_TOTAL_SUPPLY = Decimal('100000000.0')
ECON_W_TX_GROWTH = Decimal('0.5'); ECON_W_WORKER_GROWTH = Decimal('0.3'); ECON_W_WEBSITE_GROWTH = Decimal('0.2')
PAYMENT_COOLDOWN_SECONDS = 180; WORKER_TIMEOUT_SECONDS = 180; NODE_HEALTH_CHECK_TIMEOUT = 5; MINIMUM_FUNDING_AMOUNT = PRICE_PER_100_VIEWS / 2; SAVE_STATE_INTERVAL = 300
LIVE_NETWORK_CONFIG_FILE = "live_network_nodes.json"; BOOTSTRAP_CONFIG_FILE = "bootstrap_config.json"; MINER_LOCK_PORT = 19999
PHANTOM_PROBE_AMOUNT = Decimal('0.000000123')
PHANTOM_CYCLE_INTERVAL = 120
FEDERATION_SECRET_FILE = "federation_secret.key"
FEDERATION_PEERS_FILE = "federation_peers.json"
GITHUB_CONFIG_BASE_URL = "https://raw.githubusercontent.com/poybro/sokip/main/"

def setup_logging():
    log_format = '%(asctime)s [SOK_Server] [%(threadName)-18s] [%(levelname)s] - %(message)s'
    logger = logging.getLogger(); logger.setLevel(logging.INFO)
    if logger.hasHandlers(): logger.handlers.clear()
    formatter = logging.Formatter(log_format)
    file_handler = logging.FileHandler("sok_server.log", 'w', encoding='utf-8')
    file_handler.setFormatter(formatter); logger.addHandler(file_handler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter); logger.addHandler(console_handler)

def load_config_from_github(filename: str) -> Optional[Dict]:
    url = GITHUB_CONFIG_BASE_URL + filename
    logging.info(f"CONFIG: Đang tải file cấu hình từ GitHub: {url}")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        config_data = response.json()
        logging.info(f"CONFIG: Tải thành công '{filename}' từ GitHub.")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            logging.warning(f"CONFIG: Không thể lưu cache cục bộ cho '{filename}': {e}")
        return config_data
    except (requests.RequestException, json.JSONDecodeError) as e:
        logging.warning(f"CONFIG: Không thể tải hoặc phân tích file từ GitHub: {e}. Thử tải từ file cục bộ...")
        if os.path.exists(filename):
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    logging.info(f"CONFIG: Tải thành công '{filename}' từ file cục bộ (fallback).")
                    return json.load(f)
            except Exception as e_local:
                logging.error(f"CONFIG: Lỗi khi đọc file cục bộ '{filename}': {e_local}")
                return None
        else:
            logging.error(f"CONFIG: Cả GitHub và file cục bộ cho '{filename}' đều không khả dụng.")
            return None

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)
log = logging.getLogger('werkzeug'); log.disabled = True
app.logger.disabled = True

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal): return str(obj)
        return super(CustomJSONEncoder, self).default(obj)
app.json_encoder = CustomJSONEncoder

class LocalSmartBot:
    def __init__(self, core_logic_instance):
        self.core_logic = core_logic_instance
        logging.info("🤖 Bot Local thông minh đã được khởi tạo.")
    def get_reply(self, query: str, user_address: Optional[str] = None) -> str:
        query = query.lower()
        with self.core_logic.state_lock:
            if "giá" in query or "kinh tế" in query:
                if self.core_logic.historical_econ_data:
                    last_point = self.core_logic.historical_econ_data[-1]
                    return (f"Dữ liệu kinh tế mới nhất:\n"
                            f"- Giá sàn (bảo chứng): ${float(last_point.get('floor_price_usd', 0)):.8f}\n"
                            f"- Giá thị trường (ước tính): ${float(last_point.get('market_price_usd', 0)):.8f}\n"
                            f"- Tổng quỹ bảo chứng: ${float(self.core_logic.treasury_value_usd):,.2f}")
                return "Chưa có dữ liệu kinh tế để phân tích."
            if user_address:
                if "tài khoản" in query or "ví của tôi" in query or "số dư" in query:
                    profile = self.core_logic.get_user_profile_data(user_address)
                    return (f"Thông tin tài khoản của bạn ({user_address[:10]}...):\n"
                            f"- Số dư SOK: {profile.get('sok_balance', '0')} SOK")
            if "p2p" in query or "chợ" in query:
                open_orders = [o for o in self.core_logic.p2p_orders.values() if o['status'] == 'OPEN']
                return f"Hiện có {len(open_orders)} lệnh đang mở bán trên chợ P2P."
            return "Sokchain xin chào, Tôi có thể cung cấp thông tin về giá và P2P."

class PrimeAgentLogic:
    def __init__(self):
        wallet_filename = f"prime_agent_wallet_{SERVER_PORT}.pem"
        self.wallet = self._initialize_wallet(wallet_filename, f"Prime Agent on Port {SERVER_PORT}")
        
        self.admin_password = self._load_admin_config()
        self.federation_secret: Optional[bytes] = None
        self.peer_endpoints: List[str] = []
        self.trusted_peers_cache: Dict[str, Dict] = {} 
        self._load_auto_auth_config()
        
        self.federation_event_queue = Queue()
        self.balance_update_tasks: Dict[str, tuple] = {}

        self.reward_queue = Queue()
        self.active_workers: Dict[str, Dict] = {}
        self.last_reward_times: Dict[str, float] = {}
        self.state_lock = threading.RLock()
        self.websites_db: Dict[str, Dict] = {}
        self.pending_funds: Dict[str, Decimal] = {}
        self.current_best_node: Optional[str] = None
        self.is_running = threading.Event(); self.is_running.set()
        self.last_scanned_block = -1
        self.total_views_completed_session = 0
        self.p2p_orders: Dict[str, Dict] = {}
        self.public_key_cache: Dict[str, str] = {}
        self.historical_econ_data = []
        self.treasury_value_usd = ECON_INITIAL_TREASURY_USD
        self.miner_process: Optional[subprocess.Popen] = None
        self.ai_model = None
        self.local_ai_bot = None
        self._auto_discover_best_node()
        if genai and GEMINI_API_KEY:
            try:
                genai.configure(api_key=GEMINI_API_KEY)
                self.ai_model = genai.GenerativeModel('gemini-1.5-flash-latest')
                logging.info("✅ Tích hợp Gemini AI nâng cao thành công.")
            except Exception as e:
                logging.error(f"❌ Không thể khởi tạo Gemini AI. Lỗi: {e}")
        else:
            logging.warning("⚠️ Gemini API Key chưa được cấu hình. Chat AI sẽ ở chế độ local.")
        self.local_ai_bot = LocalSmartBot(self)

    def _initialize_wallet(self, filename: str, wallet_name: str) -> Wallet:
        encrypted_filename = filename.replace('.pem', '.enc')
        if os.path.exists(encrypted_filename):
            print(f"--- BẢO MẬT SERVER ---"); password = getpass(f"Nhập mật khẩu để mở khóa ví '{wallet_name}': ")
            with open(encrypted_filename, 'rb') as f: encrypted_data = f.read()
            try:
                key = base64.urlsafe_b64encode(password.encode().ljust(32)[:32]); fernet = Fernet(key); private_key_pem = fernet.decrypt(encrypted_data).decode()
                logging.info(f"✅ Ví '{wallet_name}' đã được giải mã và tải vào bộ nhớ."); return Wallet(private_key_pem=private_key_pem)
            except Exception as e: logging.critical(f"❌ Giải mã ví thất bại! Lỗi: {e}"); sys.exit(1)
        else:
            print(f"--- THIẾT LẬP VÍ MỚI ---"); password = getpass(f"Chưa có ví '{wallet_name}'. Vui lòng đặt mật khẩu mới: "); password_confirm = getpass("Xác nhận lại mật khẩu: ")
            if password != password_confirm or not password: logging.critical("Mật khẩu không khớp hoặc để trống."); sys.exit(1)
            wallet = Wallet(); private_key_pem = wallet.get_private_key_pem(); key = base64.urlsafe_b64encode(password.encode().ljust(32)[:32]); fernet = Fernet(key); encrypted_data = fernet.encrypt(private_key_pem.encode())
            with open(encrypted_filename, 'wb') as f: f.write(encrypted_data)
            print("\n" + Fore.YELLOW + "="*70)
            print("VUI LÒNG SAO CHÉP THÔNG TIN DƯỚI ĐÂY VÀO FILE CẤU HÌNH PEER (NẾU CÓ):")
            print(f'{Fore.CYAN}"address": "{wallet.get_address()}",')
            print(f'{Fore.CYAN}"public_key_pem": "{wallet.get_public_key_pem().replace(chr(10), chr(92)+chr(110))}",')
            print(Style.RESET_ALL + "="*70 + "\n")
            logging.info(f"✅ Đã tạo và mã hóa ví mới cho '{wallet_name}'. Hãy nhớ mật khẩu!"); return wallet

    def _load_admin_config(self) -> str:
        print(Fore.YELLOW + "--- CẤU HÌNH QUẢN TRỊ SERVER ---")
        password = getpass("Vui lòng nhập mật khẩu Quản trị viên cho phiên làm việc này: ")
        if password == "p0y6r0":
             logging.info("✅ Mật khẩu quản trị hợp lệ. Quyền admin đã được cấp.")
             return password
        else:
            logging.critical("❌ Mật khẩu quản trị không chính xác. Server sẽ dừng lại.")
            sys.exit(1)

    def _load_auto_auth_config(self):
        if not os.path.exists(FEDERATION_SECRET_FILE):
            logging.warning(f"Không tìm thấy file '{FEDERATION_SECRET_FILE}'. Server sẽ chạy ở chế độ độc lập.")
            return
        try:
            with open(FEDERATION_SECRET_FILE, 'rb') as f:
                self.federation_secret = base64.b64decode(f.read().strip())
            logging.info("✅ Đã tải Mật khẩu chung Liên đoàn (cho máy) thành công.")
        except Exception as e:
            logging.error(f"Lỗi nghiêm trọng khi đọc Mật khẩu Liên đoàn: {e}. Chạy ở chế độ độc lập.")
            self.federation_secret = None; return

        config = load_config_from_github(FEDERATION_PEERS_FILE)
        if not config:
            logging.error(f"Không thể tải file '{FEDERATION_PEERS_FILE}'. Không thể kết nối với các peer khác.")
            return

        try:
            try: lan_ip = socket.gethostbyname(socket.gethostname())
            except: lan_ip = '127.0.0.1'
            
            my_endpoint = f"http://{lan_ip}:{SERVER_PORT}"
            logging.info(f"Địa chỉ tự nhận diện của server này là: {my_endpoint}")
            
            self.peer_endpoints = [ep for ep in config.get("peer_endpoints", []) if ep != my_endpoint]
            if self.peer_endpoints:
                logging.info(f"Sẽ cố gắng kết nối và đồng bộ với {len(self.peer_endpoints)} peer(s) khác.")
        except Exception as e:
            logging.error(f"Lỗi khi xử lý danh sách peer: {e}")

    def _create_hmac_signature(self, message: bytes) -> str:
        if not self.federation_secret: return ""
        return hmac.new(self.federation_secret, message, hashlib.sha256).hexdigest()

    def _verify_hmac_signature(self, message: bytes, signature: str) -> bool:
        if not self.federation_secret: return False
        expected_signature = self._create_hmac_signature(message)
        return hmac.compare_digest(expected_signature, signature)

    def _handshake_with_peer(self, peer_endpoint: str) -> Optional[Dict]:
        logging.info(f"HANDSHAKE: Bắt đầu quá trình bắt tay với {peer_endpoint}...")
        try:
            nonce = os.urandom(32).hex()
            hmac_sig = self._create_hmac_signature(nonce.encode('utf-8'))
            challenge_payload = {'nonce': nonce, 'hmac': hmac_sig}
            challenge_resp = requests.post(
                f"{peer_endpoint}/api/internal/v1/handshake/challenge",
                json=challenge_payload, timeout=5
            )
            if challenge_resp.status_code != 200:
                logging.error(f"HANDSHAKE_FAIL: Peer {peer_endpoint} từ chối challenge: {challenge_resp.text}")
                return None
            response_payload = {
                'address': self.wallet.get_address(),
                'public_key_pem': self.wallet.get_public_key_pem()
            }
            response_resp = requests.post(
                f"{peer_endpoint}/api/internal/v1/handshake/response",
                json=response_payload, timeout=5
            )
            if response_resp.status_code != 200:
                logging.error(f"HANDSHAKE_FAIL: Peer {peer_endpoint} không phản hồi thông tin: {response_resp.text}")
                return None
            peer_info = response_resp.json()
            logging.info(f"HANDSHAKE_SUCCESS: Đã xác thực và nhận thông tin từ {peer_info.get('address', 'N/A')[:15]}...")
            return peer_info
        except requests.RequestException as e:
            logging.error(f"HANDSHAKE_ERROR: Lỗi kết nối khi bắt tay với {peer_endpoint}: {e}")
            return None

    def _get_peer_info(self, peer_endpoint: str) -> Optional[Dict]:
        cached_peer = next((p for p in self.trusted_peers_cache.values() if p.get('api_endpoint') == peer_endpoint), None)
        if cached_peer:
            return cached_peer
        peer_info = self._handshake_with_peer(peer_endpoint)
        if peer_info and 'address' in peer_info:
            self.trusted_peers_cache[peer_info['address']] = {**peer_info, 'api_endpoint': peer_endpoint}
            return self.trusted_peers_cache[peer_info['address']]
        return None
        
    def _sign_internal_payload(self, data: Dict) -> Dict:
        payload = {
            'data': data,
            'timestamp': int(time.time()),
            'origin_address': self.wallet.get_address()
        }
        message_to_sign = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        signature = Transaction.sign_message(self.wallet.get_private_key_pem(), message_to_sign)
        return { "payload": payload, "signature": signature }

    def broadcast_to_peers(self, endpoint: str, data: Dict):
        if not self.peer_endpoints: return
        event = { "endpoint": endpoint, "data": data }
        self.federation_event_queue.put(event)
        logging.info(f"SYNC_QUEUE: Đã thêm sự kiện '{data.get('action')}' vào hàng đợi.")

    def _federation_sync_loop(self):
        logging.info(" FEDERATION_SYNC_LOOP: Luồng đồng bộ hóa liên-prime đã bắt đầu.")
        while self.is_running.is_set():
            try:
                event = self.federation_event_queue.get(timeout=5)
                endpoint = event["endpoint"]
                data = event["data"]
                signed_message = self._sign_internal_payload(data)
        
                for peer_endpoint in self.peer_endpoints:
                    peer_info = self._get_peer_info(peer_endpoint)
                    if not peer_info:
                        logging.warning(f"SYNC_SKIP: Bỏ qua việc gửi đến peer {peer_endpoint} do không thể handshake.")
                        continue

                    target_url = f"{peer_info['api_endpoint'].rstrip('/')}{endpoint}"
                    try:
                        threading.Thread(
                            target=requests.post,
                            kwargs={'url': target_url, 'json': signed_message, 'timeout': 5}
                        ).start()
                        logging.info(f"SYNC_SENT: Đã gửi bản tin '{data.get('action')}' đến {peer_info.get('address', 'N/A')[:15]}")
                    except Exception as e:
                        logging.error(f"SYNC_FAIL: Không thể gửi bản tin. Lỗi: {e}")
            except Empty:
                continue
            except Exception as e:
                logging.error(f" FEDERATION_SYNC_LOOP: Lỗi không xác định: {e}", exc_info=True)
                time.sleep(10)

    def _fetch_balance_background_task(self, task_id: str, address: str):
        logging.info(f"BALANCE_TASK [{task_id[:8]}]: Bắt đầu lấy số dư cho ví {address[:10]}...")
        node_to_use = self.current_best_node
        
        if not node_to_use:
            logging.error(f"BALANCE_TASK [{task_id[:8]}]: Thất bại. Không có node blockchain hoạt động.")
            self.balance_update_tasks[task_id] = ("failed", "Không thể kết nối đến mạng lưới blockchain.")
            return

        try:
            time.sleep(90)
            if not self.is_running.is_set(): return
            
            response = requests.get(f"{node_to_use}/balance/{address}", timeout=10)
            if response.status_code == 200:
                balance = response.json().get("balance", "0")
                balance_str = f"{Decimal(balance):.8f}"
                self.balance_update_tasks[task_id] = ("completed", balance_str)
                logging.info(f"BALANCE_TASK [{task_id[:8]}]: Lấy số dư thành công: {balance_str} SOK.")
            else:
                error_msg = response.json().get("error", "Lỗi không xác định từ node.")
                self.balance_update_tasks[task_id] = ("failed", error_msg)
                logging.error(f"BALANCE_TASK [{task_id[:8]}]: Thất bại. Node báo lỗi: {error_msg}")
        
        except requests.RequestException as e:
            self.balance_update_tasks[task_id] = ("failed", "Lỗi mạng khi kết nối đến node.")
            logging.error(f"BALANCE_TASK [{task_id[:8]}]: Thất bại. Lỗi mạng: {e}")

    def _auto_discover_best_node(self):
        logging.info("🚀 Bắt đầu quá trình tự động tìm kiếm node blockchain tốt nhất...")
        nodes = set()
        
        live_data = load_config_from_github(LIVE_NETWORK_CONFIG_FILE)
        if live_data and "active_nodes" in live_data and isinstance(live_data["active_nodes"], list):
            nodes.update(live_data["active_nodes"])

        bootstrap_data = load_config_from_github(BOOTSTRAP_CONFIG_FILE)
        if bootstrap_data and "trusted_bootstrap_peers" in bootstrap_data and isinstance(bootstrap_data["trusted_bootstrap_peers"], dict):
            peer_urls = [p.get('last_known_address') for p in bootstrap_data["trusted_bootstrap_peers"].values() if p.get('last_known_address')]
            nodes.update(peer_urls)

        known_nodes = list(filter(None, nodes))
        if not known_nodes:
            logging.critical("❌ KHÔNG TÌM THẤY node nào từ GitHub hoặc file cục bộ. Server không thể hoạt động.")
            sys.exit(1)

        healthy_nodes = []
        threads = []
        def check_node(url, result_list):
            try:
                response = requests.get(f'{url}/chain', timeout=NODE_HEALTH_CHECK_TIMEOUT)
                if response.status_code == 200: result_list.append({"url": url, "block_height": response.json().get('length', -1)})
            except requests.RequestException: pass
        
        for node_url in known_nodes:
            thread = threading.Thread(target=check_node, args=(node_url, healthy_nodes))
            threads.append(thread)
            thread.start()
        for thread in threads: thread.join(NODE_HEALTH_CHECK_TIMEOUT + 0.5)

        if not healthy_nodes:
            logging.critical("❌ Không có node blockchain nào phản hồi. Vui lòng kiểm tra lại mạng và các node. Server sẽ dừng.")
            sys.exit(1)
            
        best_node = max(healthy_nodes, key=lambda x: x['block_height'])
        self.current_best_node = best_node['url']
        logging.info("="*70)
        logging.info(f"✅ KẾT NỐI THÀNH CÔNG: Đã tự động chọn node tốt nhất: {self.current_best_node}")
        logging.info(f"   (Chiều cao chuỗi khối: {best_node['block_height']})")
        logging.info("="*70)

    def get_miner_status(self) -> dict:
        with self.state_lock:
            if self.miner_process and self.miner_process.poll() is None: return {"status": "running", "pid": self.miner_process.pid}
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try: s.bind(("127.0.0.1", MINER_LOCK_PORT)); s.close(); return {"status": "stopped"}
                except socket.error: return {"status": "running", "pid": "N/A (External)"}

    def start_miner(self) -> (dict, int):
        with self.state_lock:
            if self.get_miner_status()['status'] == 'running': return {"error": "Tiến trình khai thác đã đang chạy."}, 409
            try:
                script_path = os.path.join(project_root, 'sok_intelligent_miner.py')
                if not os.path.exists(script_path): return {"error": f"Không tìm thấy file '{script_path}'."}, 500
                self.miner_process = subprocess.Popen([sys.executable, script_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logging.info(f"MINER_CONTROL: Đã bắt đầu tiến trình khai thác với PID: {self.miner_process.pid}")
                return {"message": "Đã bắt đầu tiến trình khai thác.", "pid": self.miner_process.pid}, 200
            except Exception as e: logging.error(f"MINER_CONTROL: Lỗi khi bắt đầu thợ mỏ: {e}", exc_info=True); return {"error": f"Lỗi hệ thống: {e}"}, 500

    def stop_miner(self) -> (dict, int):
        with self.state_lock:
            status = self.get_miner_status()
            if status['status'] == 'stopped': return {"error": "Tiến trình khai thác không đang chạy."}, 409
            if self.miner_process and self.miner_process.poll() is None:
                try:
                    pid = self.miner_process.pid; self.miner_process.terminate(); self.miner_process.wait(timeout=5)
                    logging.info(f"MINER_CONTROL: Đã dừng tiến trình khai thác PID: {pid}"); self.miner_process = None
                    return {"message": "Đã dừng tiến trình khai thác."}, 200
                except subprocess.TimeoutExpired:
                    logging.warning(f"MINER_CONTROL: Tiến trình {self.miner_process.pid} không phản hồi, buộc dừng.")
                    self.miner_process.kill(); self.miner_process = None
                    return {"message": "Đã buộc dừng tiến trình khai thác."}, 200
            else: return {"error": "Không thể dừng tiến trình không do server quản lý."}, 500

    def _load_state(self):
        if os.path.exists(STATE_FILE):
            try:
                with self.state_lock, open(STATE_FILE, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                    self.active_workers = state.get("active_workers", {})
                    self.last_reward_times = state.get("last_reward_times", {})
                    raw_db = state.get("websites_db", {})
                    self.websites_db = {url: {k: Decimal(v) if k in ['views_funded', 'views_completed'] else v for k, v in data.items()} for url, data in raw_db.items()}
                    self.last_scanned_block = state.get("last_scanned_block", -1)
                    raw_p2p = state.get("p2p_orders", {})
                    self.p2p_orders = {oid: {k: Decimal(v) if k == 'sok_amount' else v for k, v in data.items()} for oid, data in raw_p2p.items()}
                    self.public_key_cache = state.get("public_key_cache", {})
                    self.treasury_value_usd = Decimal(state.get('treasury_value_usd', str(ECON_INITIAL_TREASURY_USD)))
                    raw_pending = state.get("pending_funds", {})
                    self.pending_funds = {addr: Decimal(amt_str) for addr, amt_str in raw_pending.items()}
                    logging.info(f"Đã khôi phục trạng thái: {len(self.active_workers)} worker, {len(self.websites_db)} website, {len(self.pending_funds)} quỹ chờ.")
            except Exception as e: logging.error(f"Không thể tải tệp trạng thái: {e}")

    def _save_state(self):
        with self.state_lock:
            state = { "active_workers": self.active_workers, "last_reward_times": self.last_reward_times, "websites_db": self.websites_db, "last_scanned_block": self.last_scanned_block, "p2p_orders": self.p2p_orders, "public_key_cache": self.public_key_cache, "treasury_value_usd": str(self.treasury_value_usd), "pending_funds": self.pending_funds }
        try:
            with open(STATE_FILE + ".tmp", 'w', encoding='utf-8') as f: json.dump(state, f, indent=2, cls=CustomJSONEncoder)
            os.replace(STATE_FILE + ".tmp", STATE_FILE); logging.info("Đã lưu trạng thái vào file.")
        except Exception as e: logging.error(f"Lỗi khi lưu trạng thái: {e}")

    def start_background_threads(self):
        self._load_state()
        logging.info("="*60); logging.info("MÔ HÌNH KINH TẾ BẢO CHỨNG ĐANG CHẠY:"); logging.info(f"- Tổng phát hành SOK: {ECON_INITIAL_TOTAL_SUPPLY:,.0f}"); logging.info(f"- Quỹ Bảo chứng Ban đầu: ${ECON_INITIAL_TREASURY_USD:,.2f}"); logging.info(f"- GIÁ SÀN TỐI THIỂU: ${float(ECON_INITIAL_TREASURY_USD/ECON_INITIAL_TOTAL_SUPPLY):.8f}"); logging.info("="*60)
        threads = [ threading.Thread(target=self.find_best_node_loop, name="Node-Finder", daemon=True), threading.Thread(target=self.payment_loop, name="Worker-Payer", daemon=True), threading.Thread(target=self.cleanup_workers_loop, name="Cleaner", daemon=True), threading.Thread(target=self.funding_scanner_loop, name="Funding-Scanner", daemon=True), threading.Thread(target=self.periodic_save_loop, name="State-Saver", daemon=True), threading.Thread(target=self._econ_cycle_loop, name="Economist-Agent", daemon=True), threading.Thread(target=self.p2p_janitor_loop, name="P2P-Janitor", daemon=True), threading.Thread(target=self.phantom_agent_loop, name="Phantom-Agent", daemon=True), threading.Thread(target=self._federation_sync_loop, name="Federation-Sync", daemon=True) ]
        for t in threads: t.start()

    def phantom_agent_loop(self):
        logging.info("👻 Luồng Phantom Agent (logic broadcast) đã bắt đầu.")
        time.sleep(20)
        while self.is_running.is_set():
            try:
                all_known_nodes = set()
                live_data = load_config_from_github(LIVE_NETWORK_CONFIG_FILE)
                if live_data and "active_nodes" in live_data: all_known_nodes.update(live_data["active_nodes"])
                bootstrap_data = load_config_from_github(BOOTSTRAP_CONFIG_FILE)
                if bootstrap_data and "trusted_bootstrap_peers" in bootstrap_data: all_known_nodes.update([p.get("last_known_address") for p in bootstrap_data["trusted_bootstrap_peers"].values()])

                known_nodes_list = list(filter(None, all_known_nodes))
                if not known_nodes_list: 
                    time.sleep(PHANTOM_CYCLE_INTERVAL); continue
                
                live_nodes = []
                for node_url in known_nodes_list:
                    try:
                        if requests.get(f'{node_url}/ping', timeout=3).status_code == 200: live_nodes.append(node_url)
                    except requests.RequestException: pass
                if not live_nodes:
                    time.sleep(PHANTOM_CYCLE_INTERVAL); continue
                with self.state_lock:
                    treasury_address = self.wallet.get_address()
                    tx = Transaction(self.wallet.get_public_key_pem(), treasury_address, float(PHANTOM_PROBE_AMOUNT), sender_address=treasury_address); tx.sign(self.wallet.private_key)
                tx_dict = tx.to_dict()
                for target_node_url in live_nodes:
                    try: requests.post(f"{target_node_url}/transactions/new", json=tx_dict, timeout=10)
                    except requests.RequestException: pass
            except Exception as e: logging.error(f"👻 Phantom Agent: Lỗi không xác định trong chu kỳ. Lỗi: {e}", exc_info=True)
            
            time.sleep(PHANTOM_CYCLE_INTERVAL)

    def p2p_janitor_loop(self):
        logging.info("Luồng Dọn dẹp P2P (P2P-Janitor) đã bắt đầu.")
        while self.is_running.is_set():
            try:
                with self.state_lock:
                    orders_to_check = list(self.p2p_orders.values())
                    for order in orders_to_check:
                        if order.get('status') == 'PENDING_PAYMENT' and time.time() - order.get('accepted_at', 0) > P2P_PAYMENT_WINDOW_SECONDS:
                            order_id = order['id']; logging.warning(f"Lệnh P2P #{order_id[:8]} đã HẾT HẠN."); order['status'] = 'OPEN'; order['buyer_address'] = None; order.pop('accepted_at', None); logging.info(f"Lệnh #{order_id[:8]} đã được mở lại trên thị trường.")
            except Exception as e:
                logging.error(f"P2P_JANITOR: Lỗi không xác định: {e}")
            finally:
                time.sleep(60)

    def periodic_save_loop(self):
        logging.info("Luồng Lưu trạng thái định kỳ đã bắt đầu.");
        while self.is_running.is_set():
            try:
                self._save_state()
            except Exception as e:
                logging.error(f"STATE_SAVER: Lỗi khi lưu trạng thái: {e}")
            finally:
                time.sleep(SAVE_STATE_INTERVAL)

    def find_best_node_loop(self):
        logging.info("Luồng Tìm kiếm Node đã bắt đầu.")
        while self.is_running.is_set():
            try:
                nodes = set()
                live_data = load_config_from_github(LIVE_NETWORK_CONFIG_FILE)
                if live_data and "active_nodes" in live_data: nodes.update(live_data["active_nodes"])
                bootstrap_data = load_config_from_github(BOOTSTRAP_CONFIG_FILE)
                if bootstrap_data and "trusted_bootstrap_peers" in bootstrap_data: nodes.update([p.get('last_known_address') for p in bootstrap_data["trusted_bootstrap_peers"].values()])

                known_nodes = list(filter(None, nodes))
                if not known_nodes:
                    time.sleep(60); continue
                
                healthy_nodes = []
                threads = []
                def check_node(url, result_list):
                    try:
                        response = requests.get(f'{url}/chain', timeout=NODE_HEALTH_CHECK_TIMEOUT)
                        if response.status_code == 200: result_list.append({"url": url, "block_height": response.json().get('length', -1)})
                    except: pass
                for node_url in known_nodes:
                    thread = threading.Thread(target=check_node, args=(node_url, healthy_nodes)); thread.start(); threads.append(thread)
                for t in threads: t.join(NODE_HEALTH_CHECK_TIMEOUT + 0.5)

                with self.state_lock:
                    if healthy_nodes:
                        best_node = max(healthy_nodes, key=lambda x: x['block_height'])
                        if self.current_best_node != best_node['url']: logging.info(f"✅ Node tốt nhất mới: {best_node['url']} (Block: {best_node['block_height']})"); self.current_best_node = best_node['url']
                    else:
                        if self.current_best_node: logging.error("Mất kết nối với tất cả các node."); self.current_best_node = None
            except Exception as e:
                logging.error(f"NODE_FINDER: Lỗi không xác định: {e}")
            finally:
                time.sleep(120)

    def payment_loop(self):
        logging.info("Luồng Trả thưởng đã bắt đầu.")
        while self.is_running.is_set():
            try:
                worker_address = self.reward_queue.get(timeout=1)
                with self.state_lock: last_paid = self.last_reward_times.get(worker_address, 0); node = self.current_best_node
                if time.time() - last_paid < PAYMENT_COOLDOWN_SECONDS: continue
                if not node: self.reward_queue.put(worker_address); time.sleep(10); continue
                tx = Transaction(self.wallet.get_public_key_pem(), worker_address, float(REWARD_AMOUNT), sender_address=self.wallet.get_address()); tx.sign(self.wallet.private_key)
                response = requests.post(f"{node}/transactions/new", json=tx.to_dict(), timeout=10)
                if response.status_code == 201: logging.info(f"🚀 Giao dịch trả thưởng {float(REWARD_AMOUNT):.8f} SOK cho {worker_address[:10]}..."); self.last_reward_times[worker_address] = time.time()
                else: self.reward_queue.put(worker_address); time.sleep(5)
            except Empty: continue
            except Exception as e: logging.error(f"Lỗi luồng trả thưởng: {e}", exc_info=True); time.sleep(10)

    def cleanup_workers_loop(self):
        logging.info("Luồng Dọn dẹp Worker đã bắt đầu.")
        while self.is_running.is_set():
            try:
                with self.state_lock:
                    inactive = [addr for addr, data in self.active_workers.items() if time.time() - data.get("last_seen", 0) > WORKER_TIMEOUT_SECONDS]
                    for addr in inactive:
                        if addr in self.active_workers: del self.active_workers[addr]; logging.warning(f"Worker {addr[:10]}... đã offline. Đã xóa.")
            except Exception as e:
                logging.error(f"CLEANER: Lỗi không xác định: {e}")
            finally:
                time.sleep(60)

    def funding_scanner_loop(self):
        logging.info("Luồng Quét Thanh toán đã bắt đầu.")
        while self.is_running.is_set():
            try:
                with self.state_lock: node = self.current_best_node; last_block = self.last_scanned_block
                if not node:
                    time.sleep(30); continue
                
                response = requests.get(f"{node}/chain", timeout=10)
                if response.status_code != 200: 
                    time.sleep(60); continue
                chain = response.json().get('chain', [])
                
                with self.state_lock:
                    p2p_escrow_address = self.wallet.get_address()
                    latest_block_in_chain = last_block
                    for block in chain:
                        if block['index'] > last_block:
                            latest_block_in_chain = max(latest_block_in_chain, block['index'])
                            txs = json.loads(block.get('transactions', '[]')) if isinstance(block.get('transactions'), str) else block.get('transactions', [])
                            for tx in txs:
                                sender = tx.get('sender_address'); recipient = tx.get('recipient_address')
                                if sender and sender != "0" and sender not in self.public_key_cache:
                                    pk_pem = tx.get('sender_public_key_pem', tx.get('sender_public_key'))
                                    if pk_pem: self.public_key_cache[sender] = pk_pem
                                amount = Decimal(str(tx.get('amount', '0')))
                                if recipient == p2p_escrow_address and sender != "0":
                                    if not self._check_and_process_p2p_deposit(sender, amount, tx.get('tx_hash')) and amount >= MINIMUM_FUNDING_AMOUNT:
                                        self._handle_funding_deposit(sender, amount)
                    self.last_scanned_block = latest_block_in_chain
            except requests.RequestException: 
                time.sleep(60); continue
            except Exception as e:
                logging.error(f"FUNDING_SCANNER: Lỗi không xác định: {e}")
            
            time.sleep(60)

    def handle_ai_chat(self, query: str, user_address: Optional[str] = None):
        if self.ai_model:
            try:
                logging.info(f"AI: Đang xử lý câu hỏi bằng Gemini AI từ {'user ' + user_address[:10] if user_address else 'khách'}: '{query}'")
                context_data = {};
                with self.state_lock:
                    econ_metrics = self._econ_get_current_metrics(); last_econ_point = self.historical_econ_data[-1] if self.historical_econ_data else {}
                    context_data["market_data"] = { "floor_price_usd": f"{last_econ_point.get('floor_price_usd', 0):.8f}", "estimated_market_price_usd": f"{last_econ_point.get('market_price_usd', 0):.8f}", "treasury_value_usd": f"{self.treasury_value_usd:,.2f}", "total_sok_supply": f"{ECON_INITIAL_TOTAL_SUPPLY:,.0f}" }
                    context_data["network_stats"] = { "blockchain_height": econ_metrics.get("total_transactions", 0), "active_workers": econ_metrics.get("total_workers", 0), "managed_websites": econ_metrics.get("total_websites", 0) }
                    open_p2p_orders = [o for o in self.p2p_orders.values() if o['status'] == 'OPEN']
                    context_data["p2p_market"] = { "open_orders_count": len(open_p2p_orders), "p2p_fee_percent": f"{P2P_FEE_PERCENT}%" }
                    if user_address: context_data["user_data"] = self.get_user_profile_data(user_address)
                prompt = f"""Bạn là "Trợ lý AI của Sokchain", một trợ lý ảo thông minh và thân thiện trong hệ sinh thái Sokchain. Nhiệm vụ của bạn là trả lời câu hỏi của người dùng một cách chính xác, ngắn gọn và hữu ích dựa trên dữ liệu thời gian thực được cung cấp dưới đây. Hãy luôn trả lời bằng tiếng Việt.\n\n--- DỮ LIỆU HỆ THỐNG THỜI GIAN THỰC ---\n{json.dumps(context_data, indent=2, cls=CustomJSONEncoder)}\n--- KẾT THÚC DỮ LIỆU ---\n\nCâu hỏi của người dùng: "{query}" """
                response = self.ai_model.generate_content(prompt); return response.text
            except Exception as e: logging.error(f"AI: Lỗi khi gọi Gemini API: {e}. Chuyển sang sử dụng Bot Local."); return self.local_ai_bot.get_reply(query, user_address)
        else: logging.info(f"AI: Gemini không khả dụng. Đang xử lý bằng Bot Local: '{query}'"); return self.local_ai_bot.get_reply(query, user_address)

    def get_user_profile_data(self, address: str) -> dict:
        balance = "0"; node_to_use = self.current_best_node
        if not node_to_use: return {"error": "Không thể kết nối blockchain để lấy số dư"}
        try:
            response = requests.get(f"{node_to_use}/balance/{address}", timeout=3)
            if response.status_code == 200: balance = response.json().get("balance", "0")
        except: pass
        with self.state_lock:
            website_count = sum(1 for info in self.websites_db.values() if info.get("owner") == address)
            my_p2p_orders = [ {"id": o['id'][:8], "status": o['status'], "sok_amount": o['sok_amount']} for o in self.p2p_orders.values() if o.get('seller_address') == address or o.get('buyer_address') == address ]
        return { "address": address, "sok_balance": f"{Decimal(balance):.8f}", "website_count": website_count, "related_p2p_orders": my_p2p_orders }
    
    def p2p_accept_order(self, order_id, buyer_address):
        with self.state_lock:
            order = self.p2p_orders.get(order_id)
            if not order: return {"error": "Không tìm thấy lệnh."}, 404
            if order['status'] != 'OPEN': return {"error": "Lệnh này không có sẵn hoặc đã được người khác chấp nhận."}, 409
            if order['seller_address'] == buyer_address: return {"error": "Bạn không thể tự mua lệnh của mình."}, 403
            order['status'] = 'PENDING_PAYMENT'; order['buyer_address'] = buyer_address; order['accepted_at'] = time.time()
        logging.info(f"Lệnh P2P #{order_id[:8]} đã được chấp nhận bởi {buyer_address[:10]}. Chờ thanh toán trong {P2P_PAYMENT_WINDOW_SECONDS/60:.0f} phút.")
        return {"message": "Chấp nhận lệnh thành công. Vui lòng thanh toán cho người bán."}, 200

    def p2p_cancel_order(self, order_id: str, seller_address: str, seller_public_key_pem: str, signature: str, message: str):
        try:
            if get_address_from_public_key_pem(seller_public_key_pem) != seller_address: return {"error": "Khóa công khai không khớp với địa chỉ người bán."}, 401
        except Exception: return {"error": "Khóa công khai không hợp lệ."}, 400
        if not verify_signature(seller_public_key_pem, signature, message): return {"error": "Chữ ký không hợp lệ."}, 401
        with self.state_lock:
            order = self.p2p_orders.get(order_id)
            if not order: return {"error": "Không tìm thấy lệnh."}, 404
            if order['seller_address'] != seller_address: return {"error": "Bạn không có quyền hủy lệnh này."}, 403
            if order['status'] not in ['AWAITING_DEPOSIT', 'OPEN']: return {"error": f"Không thể hủy lệnh ở trạng thái '{order['status']}'."}, 409
            if order['status'] == 'OPEN':
                node = self.current_best_node
                if not node: return {"error": "Không thể kết nối blockchain để hoàn tiền."}, 503
                amount_to_return = float(order['sok_amount'])
                try:
                    tx = Transaction(self.wallet.get_public_key_pem(), seller_address, amount_to_return, sender_address=self.wallet.get_address()); tx.sign(self.wallet.private_key)
                    response = requests.post(f"{node}/transactions/new", json=tx.to_dict(), timeout=10)
                    if response.status_code != 201: return {"error": "Lỗi khi hoàn trả SOK ký quỹ."}, 500
                except Exception as e: return {"error": f"Lỗi hệ thống khi hoàn trả SOK: {e}"}, 500
            self.p2p_orders[order_id]['status'] = 'CANCELLED'
        return {"message": "Đã hủy lệnh thành công."}, 200

    def p2p_confirm_fiat_and_release(self, order_id: str, seller_address: str, seller_public_key_pem: str, signature: str, message: str):
        try:
            if get_address_from_public_key_pem(seller_public_key_pem) != seller_address: return {"error": "Khóa công khai không khớp với địa chỉ người bán."}, 401
        except Exception: return {"error": "Khóa công khai không hợp lệ."}, 400
        if not verify_signature(seller_public_key_pem, signature, message): return {"error": "Chữ ký không hợp lệ."}, 401
        with self.state_lock:
            order = self.p2p_orders.get(order_id)
            if not order: return {"error": "Không tìm thấy lệnh."}, 404
            if order['seller_address'] != seller_address: return {"error": "Địa chỉ không khớp."}, 403
            if order['status'] != 'PENDING_PAYMENT': return {"error": "Trạng thái lệnh không hợp lệ."}, 409
            node = self.current_best_node
            if not node: return {"error": "Không thể kết nối blockchain."}, 503
            amount_to_send = order['sok_amount']; fee = amount_to_send * (P2P_FEE_PERCENT / 100); final_amount = float(amount_to_send - fee)
            try:
                tx = Transaction(self.wallet.get_public_key_pem(), order['buyer_address'], final_amount, sender_address=self.wallet.get_address()); tx.sign(self.wallet.private_key)
                response = requests.post(f"{node}/transactions/new", json=tx.to_dict(), timeout=10)
                if response.status_code != 201: return {"error": "Lỗi gửi giao dịch."}, 500
            except Exception as e: return {"error": f"Lỗi hệ thống: {e}"}, 500
            self.p2p_orders[order_id]['status'] = 'COMPLETED'
        return {"message": f"Xác nhận thành công! {final_amount:.8f} SOK đã được chuyển."}, 200

    def _handle_funding_deposit(self, owner_address: str, amount: Decimal):
        with self.state_lock:
            target_url = next((url for url, data in self.websites_db.items() if data.get("owner") == owner_address and data.get("views_funded", Decimal('0')) == 0), None)
            if target_url:
                views_to_add = int(amount / PRICE_PER_VIEW)
                self.websites_db[target_url]["views_funded"] += Decimal(views_to_add)
                logging.info(f"✅ NẠP TIỀN: Đã cộng {views_to_add} lượt xem cho {owner_address[:10]}... vào website {target_url}")
            else:
                current_pending = self.pending_funds.get(owner_address, Decimal('0'))
                self.pending_funds[owner_address] = current_pending + amount
                logging.warning(f"⚠️ QUỸ CHỜ: Nhận được {amount} SOK từ {owner_address[:10]}... nhưng không có web chờ. Đã thêm vào quỹ chờ.")

    def _check_and_process_p2p_deposit(self, sender_address, amount, tx_hash):
        with self.state_lock:
            for order in self.p2p_orders.values():
                if order['status'] == 'AWAITING_DEPOSIT' and order['seller_address'] == sender_address and Decimal(order['sok_amount']) == amount:
                    order['status'] = 'OPEN'; order['tx_hash_proof'] = tx_hash; logging.info(f"💰 Ký quỹ P2P thành công cho lệnh #{order['id'][:8]}."); return True
        return False

    def p2p_create_order(self, seller_address, sok_amount_str, fiat_details):
        try: sok_amount = Decimal(sok_amount_str)
        except: return {"error": "Số SOK không hợp lệ"}, 400
        if sok_amount <= 0: return {"error": "Số SOK phải lớn hơn 0"}, 400
        order_id = str(uuid.uuid4()); new_order = {"id": order_id, "seller_address": seller_address, "sok_amount": sok_amount, "fiat_details": fiat_details, "status": "AWAITING_DEPOSIT", "buyer_address": None, "created_at": time.time()}
        with self.state_lock: self.p2p_orders[order_id] = new_order
        return {"message": "Tạo lệnh thành công.", "order": new_order, "escrow_address": self.wallet.get_address()}, 201

    def _econ_load_data(self):
        if not os.path.exists(ECON_DATA_FILE): return
        try:
            with open(ECON_DATA_FILE, 'r', encoding='utf-8') as f: self.historical_econ_data = json.load(f, parse_float=Decimal)
        except Exception: pass

    def _econ_save_data(self):
        try:
            with open(ECON_DATA_FILE, 'w', encoding='utf-8') as f: json.dump(self.historical_econ_data, f, indent=2, cls=CustomJSONEncoder)
        except IOError: pass

    def _econ_generate_chart(self):
        if len(self.historical_econ_data) < 2: return
        try:
            data_copy = self.historical_econ_data[:]
            timestamps = [datetime.fromtimestamp(float(d['timestamp'])) for d in data_copy]
            market_prices = [float(d['market_price_usd']) for d in data_copy]
            floor_prices = [float(d['floor_price_usd']) for d in data_copy]
            treasury_values = [float(d.get('treasury_value_usd', 0)) for d in data_copy]
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=timestamps, y=floor_prices, mode='lines', name='Giá Sàn (Bảo chứng)', line=dict(color='green', dash='dot')))
            fig.add_trace(go.Scatter(x=timestamps, y=market_prices, mode='lines+markers', name='Giá Thị trường (Ước tính)', line=dict(color='blue')))
            fig.add_trace(go.Bar(x=timestamps, y=treasury_values, name='Tổng Quỹ Bảo chứng (USD)', yaxis='y2', marker_color='lightsalmon', opacity=0.6))
            fig.update_layout(title_text='<b>Mô hình Định giá Bảo chứng & Sức khỏe Mạng lưới Sokchain</b>', yaxis=dict(title='<b>Giá SOK (USD)</b>', type='log'), yaxis2=dict(title='Giá trị Quỹ (USD)', overlaying='y', side='right', showgrid=False), legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01), template='plotly_white', hovermode='x unified')
            fig.write_html(ECON_CHART_FILE)
            logging.info(f"Agent Kinh tế: ✅ Biểu đồ đã được cập nhật.")
        except Exception as e: logging.error(f"Lỗi khi vẽ biểu đồ kinh tế: {e}")

    def _econ_get_current_metrics(self):
        with self.state_lock: node = self.current_best_node
        blockchain_height = 0
        if node:
            try:
                res = requests.get(f"{node}/chain", timeout=5);
                if res.ok: blockchain_height = res.json().get("length", 0)
            except: pass
        with self.state_lock: total_p2p_escrow = sum(o['sok_amount'] for o in self.p2p_orders.values() if o['status'] == 'OPEN')
        return {"total_workers": len(self.active_workers), "total_websites": len(self.websites_db), "total_p2p_escrow_sok": total_p2p_escrow, "total_transactions": blockchain_height}

    def _econ_run_cycle(self):
        current_metrics = self._econ_get_current_metrics(); current_metrics["timestamp"] = time.time()
        last_analysis = self.historical_econ_data[-1] if self.historical_econ_data else None
        if last_analysis:
            last_market_price = Decimal(str(last_analysis.get('market_price_usd', ECON_INITIAL_TREASURY_USD / ECON_INITIAL_TOTAL_SUPPLY)))
            new_transactions = current_metrics['total_transactions'] - last_analysis.get('total_transactions', 0)
            avg_fee_percent = (PLATFORM_FEE_PERCENT + P2P_FEE_PERCENT) / 2 / 100
            revenue_sok = Decimal(str(new_transactions)) * Decimal('1.0') * avg_fee_percent
            revenue_usd = revenue_sok * last_market_price
            with self.state_lock: self.treasury_value_usd += revenue_usd
        with self.state_lock: current_treasury_usd = self.treasury_value_usd
        total_supply = ECON_INITIAL_TOTAL_SUPPLY
        floor_price_usd = current_treasury_usd / total_supply
        if not last_analysis: activity_multiplier = Decimal('0.0')
        else:
            tx_growth = (current_metrics['total_transactions'] - last_analysis.get('total_transactions', 0)) / max(1, last_analysis.get('total_transactions', 1))
            worker_growth = (current_metrics['total_workers'] - last_analysis.get('total_workers', 0)) / max(1, last_analysis.get('total_workers', 1))
            website_growth = (current_metrics['total_websites'] - last_analysis.get('total_websites', 0)) / max(1, last_analysis.get('total_websites', 1))
            smoothed_tx_growth = Decimal(str(math.log1p(max(0, tx_growth)))); smoothed_worker_growth = Decimal(str(math.log1p(max(0, worker_growth)))); smoothed_website_growth = Decimal(str(math.log1p(max(0, website_growth))))
            activity_multiplier = (ECON_W_TX_GROWTH * smoothed_tx_growth) + (ECON_W_WORKER_GROWTH * smoothed_worker_growth) + (ECON_W_WEBSITE_GROWTH * smoothed_website_growth)
        current_price_usd = floor_price_usd * (Decimal('1.0') + activity_multiplier)
        analysis_result = {**current_metrics, "floor_price_usd": floor_price_usd, "market_price_usd": current_price_usd, "activity_multiplier": activity_multiplier, "treasury_value_usd": current_treasury_usd}
        self.historical_econ_data.append(analysis_result); self._econ_save_data(); self._econ_generate_chart()
    
    def _econ_cycle_loop(self):
        self._econ_load_data()
        while self.is_running.is_set():
            try:
                self._econ_run_cycle()
            except Exception as e:
                logging.error(f"Agent Kinh tế: Lỗi nghiêm trọng: {e}", exc_info=True)
            finally:
                time.sleep(ECON_ANALYSIS_INTERVAL)

    def shutdown(self):
        if self.is_running.is_set():
            print("\n\nĐang dừng Server..."); self.is_running.clear(); self.stop_miner(); self._save_state(); logging.info("Server đã dừng.")

# --- DECORATOR VÀ API ROUTES ---

def internal_api_authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        message = request.get_json()
        if not all(k in message for k in ['payload', 'signature']):
            return jsonify({"error": "Request nội bộ không hợp lệ."}), 400
        
        payload = message['payload']
        signature = message['signature']
        origin_address = payload.get('origin_address')

        peer_info = core_logic.trusted_peers_cache.get(origin_address)
        if not peer_info:
            logging.warning(f"SYNC_REJECT: Nhận được request từ peer chưa được xác thực: {origin_address}")
            return jsonify({"error": "Peer chưa được xác thực qua handshake."}), 403
            
        public_key_pem = peer_info.get('public_key_pem')
        message_to_verify = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        if not verify_signature(public_key_pem, signature, message_to_verify):
            logging.warning(f"SYNC_REJECT: Chữ ký không hợp lệ từ {origin_address}")
            return jsonify({"error": "Chữ ký không hợp lệ."}), 401
            
        request.validated_payload = payload
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def dashboard_page(): return render_template('dashboard.html')
@app.route('/manage')
def manage_page(): return render_template('manage.html')
@app.route('/market')
def market_page(): return render_template('p2p_market.html')
@app.route('/chat')
def chat_page(): return render_template('ai_chat.html')
@app.route('/favicon.ico')
def favicon(): return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    data = request.get_json()
    if data and 'worker_address' in data:
        with core_logic.state_lock: core_logic.active_workers[data['worker_address']] = { "last_seen": time.time(), "ip": request.remote_addr, **data }
    return jsonify({"status": "ok"})

@app.route('/api/v1/dashboard_stats')
def get_dashboard_stats():
    with core_logic.state_lock:
        active_workers=len(core_logic.active_workers); total_websites=len(core_logic.websites_db); views_completed=core_logic.total_views_completed_session
        open_p2p_orders=len([o for o in core_logic.p2p_orders.values() if o['status'] == 'OPEN'])
    chain_height = -1; node_to_use = core_logic.current_best_node
    if node_to_use:
        try:
            response = requests.get(f"{node_to_use}/chain", timeout=3)
            if response.status_code == 200: chain_height = response.json().get('length', 0)
        except: pass 
    return jsonify({"active_workers": active_workers, "total_websites": total_websites, "views_completed_session": views_completed, "blockchain_height": chain_height, "status": "Online" if core_logic.current_best_node else "Connecting...", "open_p2p_orders": open_p2p_orders})

@app.route('/api/create_wallet', methods=['POST'])
def create_wallet_api():
    wallet = Wallet(); return jsonify({"address": wallet.get_address(), "public_key_pem": wallet.get_public_key_pem(), "private_key_pem": wallet.get_private_key_pem()})

@app.route('/api/wallet_from_pk', methods=['POST'])
def get_wallet_from_pk():
    data = request.get_json(); pk_pem = data.get('private_key_pem')
    if not pk_pem: return jsonify({"error": "Thiếu Private Key PEM."}), 400
    try: wallet = Wallet(private_key_pem=pk_pem); return jsonify({"address": wallet.get_address(), "public_key_pem": wallet.get_public_key_pem()})
    except Exception: return jsonify({"error": "Private Key không hợp lệ."}), 400

@app.route('/api/get_balance/<address>', methods=['GET'])
def get_balance_api(address):
    node_to_use = core_logic.current_best_node
    if not node_to_use: return jsonify({"error": "Không có node blockchain nào hoạt động."}), 503
    try: response = requests.get(f"{node_to_use}/balance/{address}", timeout=5); response.raise_for_status(); return jsonify(response.json())
    except requests.exceptions.RequestException: return jsonify({"error": "Không thể kết nối đến node blockchain"}), 503

@app.route('/api/direct_fund', methods=['POST'])
def direct_fund_api():
    data = request.get_json(); pk_pem = data.get('private_key_pem'); recipient = data.get('recipient_address'); amount_str = data.get('amount')
    if not all([pk_pem, recipient, amount_str]): return jsonify({"error": "Thiếu thông tin."}), 400
    try:
        sender_wallet = Wallet(private_key_pem=pk_pem); sender_address = sender_wallet.get_address(); amount = float(amount_str); node_to_use = core_logic.current_best_node
        if not node_to_use: return jsonify({"error": "Không có node blockchain nào hoạt động."}), 503
        balance_resp = requests.get(f"{node_to_use}/balance/{sender_address}", timeout=5)
        if balance_resp.json().get('balance', 0) < amount: return jsonify({"error": "Số dư không đủ."}), 402
        tx = Transaction(sender_wallet.get_public_key_pem(), recipient, amount, sender_address=sender_address); tx.sign(sender_wallet.private_key)
        broadcast_resp = requests.post(f"{node_to_use}/transactions/new", json=tx.to_dict(), timeout=10); broadcast_resp.raise_for_status()
        return jsonify({"message": f"Đã gửi thành công {amount} SOK!"}), 201
    except Exception: return jsonify({"error": "Lỗi server khi xử lý giao dịch."}), 500

@app.route('/ping', methods=['GET'])
def ping(): return jsonify({"status": "alive"})

@app.route('/api/v1/payment_info', methods=['GET'])
def get_payment_info():
    return jsonify({ "treasury_address": core_logic.wallet.get_address(), "price_per_100_views": str(PRICE_PER_100_VIEWS), "minimum_funding": str(MINIMUM_FUNDING_AMOUNT), "p2p_fee_percent": str(P2P_FEE_PERCENT)})

@app.route('/api/v1/websites/add', methods=['POST'])
def add_website():
    data = request.get_json(); new_url = data.get('url', '').strip(); owner_pk_pem = data.get('owner_pk_pem')
    if not (new_url and owner_pk_pem): return jsonify({"error": "Thiếu URL hoặc Public Key."}), 400
    if not (new_url.startswith('http://') or new_url.startswith('https://')): new_url = 'https://' + new_url
    try: owner_address = get_address_from_public_key_pem(owner_pk_pem)
    except Exception: return jsonify({"error": "Public Key không hợp lệ."}), 400
    with core_logic.state_lock:
        if any(w_url == new_url for w_url in core_logic.websites_db): return jsonify({"error": "Website đã tồn tại."}), 409
        
        website_data = {"owner": owner_address, "views_funded": Decimal('0'), "views_completed": Decimal('0')}
        core_logic.websites_db[new_url] = website_data
        message = f"Thêm website thành công! Vui lòng nạp SOK để kích hoạt."
        
        if owner_address in core_logic.pending_funds:
            pending_amount = core_logic.pending_funds.pop(owner_address)
            views_to_add = int(pending_amount / PRICE_PER_VIEW)
            core_logic.websites_db[new_url]["views_funded"] += Decimal(views_to_add)
            message = f"Thêm website thành công! Đã tự động áp dụng {pending_amount} SOK từ quỹ chờ của bạn."
            logging.info(f"✅ QUỸ CHỜ: Đã áp dụng {pending_amount} SOK cho website mới {new_url} của {owner_address[:10]}")
    
    sync_data = {'action': 'add', 'url': new_url, 'data': {k: str(v) for k, v in website_data.items()}}
    core_logic.broadcast_to_peers('/api/internal/v1/sync/website', sync_data)
            
    return jsonify({"message": message}), 201

@app.route('/api/v1/websites/list', methods=['GET'])
def list_websites():
    owner_address = request.args.get('owner')
    if not owner_address: return jsonify({"error": "Thiếu địa chỉ chủ sở hữu."}), 400
    with core_logic.state_lock: owner_sites = [{"url": url, "info": info} for url, info in core_logic.websites_db.items() if info.get("owner") == owner_address]
    return jsonify(owner_sites)

@app.route('/api/v1/websites/remove', methods=['POST'])
def remove_website():
    data = request.get_json(); url_to_remove = data.get('url'); owner_address = data.get('owner_address')
    if not (url_to_remove and owner_address): return jsonify({"error": "Thiếu thông tin."}), 400
    with core_logic.state_lock:
        if url_to_remove not in core_logic.websites_db: return jsonify({"error": "Website không tồn tại."}), 404
        if core_logic.websites_db[url_to_remove].get("owner") != owner_address: return jsonify({"error": "Bạn không có quyền xóa."}), 403
        del core_logic.websites_db[url_to_remove]; logging.info(f"🗑️  Website đã được xóa: {url_to_remove}")
    
    sync_data = {'action': 'remove', 'url': url_to_remove}
    core_logic.broadcast_to_peers('/api/internal/v1/sync/website', sync_data)

    return jsonify({"message": f"Đã xóa thành công: {url_to_remove}"}), 200

@app.route('/api/v1/websites/get_one', methods=['GET'])
def get_website_to_view():
    with core_logic.state_lock:
        funded_websites = [url for url, data in core_logic.websites_db.items() if data.get("views_funded", Decimal('0')) > 0]
        if not funded_websites: return jsonify({"error": "Hiện tại đã hết website để xem."}), 404
        random_url = random.choice(funded_websites)
    return jsonify({"url": random_url, "viewId": f"view_{random_url}_{int(time.time() * 1000)}"})

@app.route('/api/v1/views/submit_proof', methods=['POST'])
def submit_view_proof():
    data = request.get_json(); view_id = data.get('viewId'); worker_address = data.get('worker_address')
    if not (view_id and worker_address): return jsonify({"error": "Dữ liệu không hợp lệ."}), 400
    try:
        url_viewed = "_".join(view_id.split('_')[1:-1])
        with core_logic.state_lock:
            website_data = core_logic.websites_db.get(url_viewed)
            if website_data and website_data.get("views_funded", Decimal('0')) > 0:
                website_data["views_funded"] -= 1; website_data["views_completed"] = website_data.get("views_completed", Decimal('0')) + 1; core_logic.total_views_completed_session += 1; core_logic.reward_queue.put(worker_address)
                return jsonify({"message": "Xác nhận thành công! Phần thưởng đang được xử lý."}), 200
            return jsonify({"error": "Website đã hết tín dụng hoặc không tồn tại."}), 402
    except Exception: return jsonify({"error": "Lỗi nội bộ server."}), 500

@app.route('/api/v1/workers/list_by_type', methods=['GET'])
def list_workers_by_type():
    with core_logic.state_lock:
        workers = { 'backlink_service': [], 'view_worker': [] };
        for address, data in core_logic.active_workers.items(): worker_info = { "address": address, **data }; workers.get(data.get('type', 'view_worker'), workers['view_worker']).append(worker_info)
    return jsonify(workers)

@app.route('/api/v1/p2p/orders/create', methods=['POST'])
def p2p_create_order_api():
    data = request.get_json()
    response, code = core_logic.p2p_create_order(data.get('seller_address'), data.get('sok_amount'), data.get('fiat_details'))
    return jsonify(response), code

@app.route('/api/v1/p2p/orders/list', methods=['GET'])
def p2p_list_orders_api():
    with core_logic.state_lock: open_orders = [o for o in core_logic.p2p_orders.values() if o['status'] == 'OPEN']
    return jsonify(sorted(open_orders, key=lambda x: x['created_at']))

@app.route('/api/v1/p2p/orders/<order_id>/accept', methods=['POST'])
def p2p_accept_order_api(order_id):
    data = request.get_json()
    response, code = core_logic.p2p_accept_order(order_id, data.get('buyer_address'))
    return jsonify(response), code

@app.route('/api/v1/p2p/orders/<order_id>/confirm', methods=['POST'])
def p2p_confirm_payment_api(order_id):
    data = request.get_json()
    if not data: return jsonify({"error": "Request body không được để trống."}), 400
    message_data = data.get('message_data'); signature = data.get('signature'); public_key_pem = data.get('public_key_pem')
    if not all([message_data, signature, public_key_pem]): return jsonify({"error": "Thiếu message_data, signature, hoặc public_key_pem."}), 400
    seller_address = message_data.get('address')
    if message_data.get('order_id') != order_id: return jsonify({"error": "Xung đột ID lệnh."}), 400
    message_to_verify = json.dumps(message_data, sort_keys=True, separators=(',', ':'))
    response, code = core_logic.p2p_confirm_fiat_and_release(order_id, seller_address, public_key_pem, signature, message_to_verify)
    return jsonify(response), code

@app.route('/api/v1/p2p/orders/<order_id>/cancel', methods=['POST'])
def p2p_cancel_order_api(order_id):
    data = request.get_json()
    if not data: return jsonify({"error": "Request body không được để trống."}), 400
    message_data = data.get('message_data'); signature = data.get('signature'); public_key_pem = data.get('public_key_pem')
    if not all([message_data, signature, public_key_pem]): return jsonify({"error": "Thiếu message_data, signature, hoặc public_key_pem."}), 400
    seller_address = message_data.get('address')
    if message_data.get('order_id') != order_id: return jsonify({"error": "Xung đột ID lệnh."}), 400
    message_to_verify = json.dumps(message_data, sort_keys=True, separators=(',', ':'))
    response, code = core_logic.p2p_cancel_order(order_id, seller_address, public_key_pem, signature, message_to_verify)
    return jsonify(response), code

@app.route('/api/v1/p2p/my_orders', methods=['GET'])
def p2p_get_my_orders_api():
    user_address = request.args.get('address')
    if not user_address: return jsonify({"error": "Thiếu địa chỉ ví."}), 400
    with core_logic.state_lock:
        my_orders = [o for o in core_logic.p2p_orders.values() if o.get('seller_address') == user_address or o.get('buyer_address') == user_address]
    return jsonify(sorted(my_orders, key=lambda x: x['created_at'], reverse=True))

@app.route('/api/v1/user_profile/<address>', methods=['GET'])
def get_user_profile(address):
    if not address: return jsonify({"error": "Thiếu địa chỉ ví."}), 400
    return jsonify(core_logic.get_user_profile_data(address))

@app.route('/api/v1/transaction_history/<address>', methods=['GET'])
def get_transaction_history_api(address):
    if not address: return jsonify({"error": "Yêu cầu địa chỉ ví."}), 400
    node_to_use = core_logic.current_best_node
    if not node_to_use: return jsonify({"error": "Không có node blockchain nào đang hoạt động để truy vấn."}), 503
    try:
        response = requests.get(f"{node_to_use}/chain", timeout=15); response.raise_for_status()
        chain_data = response.json().get('chain', [])
        history = []; user_address_lower = address.lower()
        for block in chain_data:
            transactions = block.get('transactions', [])
            if isinstance(transactions, str):
                try: transactions = json.loads(transactions)
                except json.JSONDecodeError: continue
            for tx in transactions:
                sender = tx.get('sender_address'); recipient = tx.get('recipient_address'); formatted_tx = None
                if sender and sender.lower() == user_address_lower:
                    formatted_tx = {"type": "sent", "from": sender, "to": recipient, "amount": str(tx.get('amount', '0')), "timestamp": tx.get('timestamp'), "tx_hash": tx.get('tx_hash') or hash_data(tx)}
                elif recipient and recipient.lower() == user_address_lower:
                    formatted_tx = {"type": "received", "from": sender, "to": recipient, "amount": str(tx.get('amount', '0')), "timestamp": tx.get('timestamp'), "tx_hash": tx.get('tx_hash') or hash_data(tx)}
                if formatted_tx: history.append(formatted_tx)
        return jsonify(history), 200
    except requests.exceptions.RequestException as e:
        logging.error(f"Lỗi khi lấy lịch sử giao dịch từ node {node_to_use}: {e}")
        return jsonify({"error": f"Lỗi kết nối đến node blockchain: {e}"}), 503
    except Exception as e:
        logging.error(f"Lỗi không xác định khi xử lý lịch sử giao dịch cho {address}: {e}", exc_info=True)
        return jsonify({"error": "Lỗi server nội bộ khi xử lý yêu cầu."}), 500

@app.route('/api/v1/explorer_data', methods=['GET'])
def get_explorer_data():
    node_to_use = core_logic.current_best_node
    if not node_to_use: return jsonify({"error": "Không thể kết nối đến node."}), 503
    try:
        chain_len_resp = requests.get(f"{node_to_use}/chain", timeout=3).json(); start_block = max(0, chain_len_resp.get('length', 0) - 50)
        chain_resp = requests.get(f'{node_to_use}/chain?start={start_block}', timeout=10)
        if chain_resp.status_code == 200:
            chain_data = chain_resp.json().get('chain', [])
            for block in chain_data:
                if isinstance(block.get('transactions'), str):
                    try: block['transactions'] = json.loads(block['transactions'])
                    except: block['transactions'] = []
            return jsonify({ "chain": chain_data })
        return jsonify({"error": "Node không phản hồi hợp lệ."}), 500
    except requests.exceptions.RequestException as e: return jsonify({"error": f"Lỗi kết nối đến node: {e}"}), 503

@app.route('/api/v1/ai/chat', methods=['POST'])
def ai_chat_api():
    data = request.get_json()
    if not data or 'query' not in data: return jsonify({"error": "Thiếu câu hỏi (query)."}), 400
    return jsonify({"reply": core_logic.handle_ai_chat(data['query'], data.get('address'))})

@app.route('/api/v1/miner/status', methods=['GET'])
def get_miner_status_api(): return jsonify(core_logic.get_miner_status())

@app.route('/api/v1/miner/start', methods=['POST'])
def start_miner_api():
    response, code = core_logic.start_miner(); return jsonify(response), code

@app.route('/api/v1/miner/stop', methods=['POST'])
def stop_miner_api():
    response, code = core_logic.stop_miner(); return jsonify(response), code

@app.route('/api/v1/worker/validate_key', methods=['POST'])
def validate_worker_key_api():
    data = request.get_json()
    if not data or 'key' not in data: return jsonify({"valid": False, "error": "Thiếu key."}), 400
    submitted_key = data.get('key'); worker_address = data.get('worker_address', 'N/A')
    if submitted_key == VALID_ACTIVATION_KEY:
        logging.info(f"✅ Key kích hoạt hợp lệ được cung cấp bởi worker: {worker_address[:15]}...")
        return jsonify({"valid": True, "message": "Key hợp lệ.", "max_instances": 6})
    else:
        logging.warning(f"❌ Worker {worker_address[:15]}... đã cung cấp key kích hoạt không hợp lệ.")
        return jsonify({"valid": False, "error": "Key không hợp lệ."}), 403

@app.route('/api/v1/guardian/all_websites', methods=['GET'])
def get_all_websites_for_guardian():
    auth_pass = request.headers.get('X-Admin-Password')
    if auth_pass != core_logic.admin_password:
        return jsonify({"error": "Không có quyền truy cập."}), 403
    with core_logic.state_lock:
        all_urls = list(core_logic.websites_db.keys())
    return jsonify({"websites": all_urls})

@app.route('/api/v1/guardian/force_delete', methods=['POST'])
def force_delete_website_by_guardian():
    auth_pass = request.headers.get('X-Admin-Password')
    if auth_pass != core_logic.admin_password:
        return jsonify({"error": "Không có quyền truy cập."}), 403
    data = request.get_json(); url_to_delete = data.get('url')
    if not url_to_delete: return jsonify({"error": "Thiếu URL cần xóa."}), 400
    with core_logic.state_lock:
        if url_to_delete in core_logic.websites_db:
            del core_logic.websites_db[url_to_delete]
            logging.info(f"[Admin Action via Guardian] Website '{url_to_delete}' đã bị xóa thủ công.")
            return jsonify({"message": f"Website '{url_to_delete}' đã được xóa thành công."}), 200
        else:
            return jsonify({"error": "Website không tồn tại trong cơ sở dữ liệu."}), 404    

@app.route('/api/v1/miners/list', methods=['GET'])
def list_miners_api():
    with core_logic.state_lock:
        all_workers = core_logic.active_workers.items()
        miners = [{"address": address, **data} for address, data in all_workers if data.get('type') == 'miner']
    return jsonify(miners)

@app.route('/api/internal/v1/sync/website', methods=['POST'])
@internal_api_authenticated
def sync_website_from_peer():
    payload = request.validated_payload
    sync_data = payload.get('data', {})
    action = sync_data.get('action'); url = sync_data.get('url')
    if not all([action, url]): return jsonify({"error": "Dữ liệu đồng bộ không đầy đủ."}), 400
    logging.info(f"SYNC_RECEIVED: Nhận được bản tin '{action}' cho website '{url}' từ {payload['origin_address'][:10]}")
    with core_logic.state_lock:
        if action == 'add':
            website_data_str = sync_data.get('data', {})
            website_data = {k: Decimal(v) if k in ['views_funded', 'views_completed'] else v for k, v in website_data_str.items()}
            core_logic.websites_db[url] = website_data
        elif action == 'remove':
            if url in core_logic.websites_db:
                del core_logic.websites_db[url]
    return jsonify({"status": "ok"}), 200

@app.route('/api/internal/v1/handshake/challenge', methods=['POST'])
def handshake_challenge():
    data = request.get_json(); nonce = data.get('nonce'); hmac_sig = data.get('hmac')
    if not all([nonce, hmac_sig]): return jsonify({"error": "Challenge không hợp lệ."}), 400
    if not core_logic._verify_hmac_signature(nonce.encode('utf-8'), hmac_sig):
        logging.warning(f"HANDSHAKE_REJECT: HMAC không hợp lệ từ {request.remote_addr}")
        return jsonify({"error": "Xác thực Mật khẩu chung thất bại."}), 403
    return jsonify({"status": "challenge_ok"}), 200

@app.route('/api/internal/v1/handshake/response', methods=['POST'])
def handshake_response():
    peer_info = request.get_json()
    if not all(k in peer_info for k in ['address', 'public_key_pem']):
        return jsonify({"error": "Thông tin peer không đầy đủ."}), 400
    core_logic.trusted_peers_cache[peer_info['address']] = peer_info
    logging.info(f"HANDSHAKE_COMPLETED: Đã nhận và lưu thông tin từ peer {peer_info['address'][:15]}")
    my_info = {
        'address': core_logic.wallet.get_address(),
        'public_key_pem': core_logic.wallet.get_public_key_pem()
    }
    return jsonify(my_info), 200

@app.route('/api/v1/user/request_balance_update', methods=['POST'])
def request_balance_update():
    data = request.get_json()
    address = data.get('address')
    if not address:
        return jsonify({"error": "Thiếu địa chỉ ví."}), 400

    task_id = str(uuid.uuid4())
    core_logic.balance_update_tasks[task_id] = ("pending", None)
    
    threading.Thread(
        target=core_logic._fetch_balance_background_task,
        args=(task_id, address),
        daemon=True
    ).start()

    return jsonify({"task_id": task_id, "status": "pending"}), 202

@app.route('/api/v1/user/get_balance_result/<task_id>', methods=['GET'])
def get_balance_result(task_id):
    result = core_logic.balance_update_tasks.get(task_id)
    
    if not result:
        return jsonify({"error": "Không tìm thấy tác vụ."}), 404
        
    status, data = result
    
    response = {"task_id": task_id, "status": status}
    if status == "completed":
        response["balance"] = data
    elif status == "failed":
        response["error_message"] = data

    if status in ["completed", "failed"]:
        del core_logic.balance_update_tasks[task_id]

    return jsonify(response), 200

if __name__ == '__main__':
    if len(sys.argv) > 1:
        try:
            SERVER_PORT = int(sys.argv[1])
        except ValueError:
            print(f"Lỗi: Port '{sys.argv[1]}' không hợp lệ. Sử dụng port mặc định {SERVER_PORT}.")
    
    setup_logging()
    core_logic = None
    try:
        core_logic = PrimeAgentLogic()
        core_logic.start_background_threads()
        try: lan_ip = socket.gethostbyname(socket.gethostname())
        except: lan_ip = '127.0.0.1'
        colorama_init(autoreset=True)
        print(Fore.CYAN + Style.BRIGHT + "="*70)
        print(Fore.GREEN + Style.BRIGHT + f"   ΣOK CHAIN - AIO SERVER v14.2 (Stable Loops on Port {SERVER_PORT})")
        print(Fore.YELLOW + "    " + "-"*62)
        print(Fore.WHITE +  f"    Server đang lắng nghe tại: http://{lan_ip}:{SERVER_PORT}")
        print(Fore.GREEN + f"    Bảng điều khiển & Khai thác: http://{lan_ip}:{SERVER_PORT}")
        print(Fore.CYAN + Style.BRIGHT + "="*70)
        serve(app, host='0.0.0.0', port=SERVER_PORT, threads=20)
    except (KeyboardInterrupt, SystemExit):
        logging.info("Server đang dừng...")
    finally: 
        if core_logic and core_logic.is_running.is_set():
            core_logic.shutdown()
