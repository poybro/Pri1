#!/usr/bin/env python3
# sok_node_ultimate_shared_db.py - Node Sokchain v4.0 (Tối thượng & Dùng chung CSDL)
# -*- coding: utf-8 -*-

"""
Phiên bản Node Tối thượng, Tương tác và Dùng chung Database.

- Yêu cầu người dùng nhập liệu để cấu hình khi khởi động.
- Kích hoạt dịch vụ Seeder mạnh mẽ nếu cung cấp đúng mật mã.
- Cổng mặc định cho Node là 5000.
- Luôn sử dụng 'blockchain.sqlite' và 'node_wallet.pem' cho mọi instance.
- Tích hợp Đồng bộ hóa Thông minh (Smart Sync) để bảo vệ phần cứng.

CẢNH BÁO QUAN TRỌNG:
Tất cả các node khởi động từ file này sẽ cùng sử dụng MỘT file database.
TUYỆT ĐỐI KHÔNG CHẠY HAI NODE CÙNG LÚC để tránh làm hỏng dữ liệu.
"""

import os
import sys
import logging
import time
import threading
import requests
import random
import json
import socket
from typing import Optional
from colorama import init, Fore, Style
from waitress import serve
from flask import jsonify

# --- THIẾT LẬP MÔI TRƯỜNG & ĐƯỜNG DẪN ---
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')
init(autoreset=True)

# --- IMPORT CÁC THÀNH PHẦN CỐT LÕI ---
try:
    from sok.node_api import create_app
    from sok.utils import Config
    from sok.wallet import Wallet
    from sok.blockchain import Blockchain, Block
    from run_ranger_agent import run_deep_discovery_cycle, load_bootstrap_peers
except ImportError as e:
    print(Fore.RED + f"\n[LỖI IMPORT] Không thể tải các thành phần cần thiết: {e}")
    sys.exit(1)

# --- CẤU HÌNH ĐỒNG BỘ HÓA THÔNG MINH ---
FAST_SYNC_INTERVAL = 15
NORMAL_SYNC_INTERVAL = 75

# (Các class SeederService và P2PManager giữ nguyên như phiên bản trước vì đã tối ưu)
class SeederService:
    REFRESH_INTERVAL_SECONDS = 5 * 60
    def __init__(self):
        self.logger = logging.getLogger("SeederService")
        self.is_running = True
        self.bootstrap_peers = load_bootstrap_peers()
        if not self.bootstrap_peers: self.is_running = False 
        self.discovery_thread = threading.Thread(target=self.run_discovery_loop, daemon=True, name="Seeder-Discovery")
        if self.is_running: self.discovery_thread.start()
    def stop(self): self.is_running = False
    def run_discovery_loop(self):
        while self.is_running:
            try: run_deep_discovery_cycle(self.bootstrap_peers); time.sleep(self.REFRESH_INTERVAL_SECONDS)
            except Exception: time.sleep(60)
    def get_active_peers(self) -> list:
        live_file = os.path.join(project_root, 'live_network_nodes.json')
        if os.path.exists(live_file):
            try: return json.load(open(live_file, 'r', encoding='utf-8')).get("active_nodes", [])
            except Exception: pass
        return []

class P2PManager:
    def __init__(self, blockchain: Blockchain, node_wallet: Wallet, node_port: int, host_ip: str, seeder_node_url: Optional[str] = None):
        self.blockchain = blockchain; self.node_wallet = node_wallet; self.node_port = node_port; self.host_ip = host_ip; self.seeder_node_url = seeder_node_url;
        self.logger = logging.getLogger("P2PManager"); self.is_running = True; self.sync_interval = FAST_SYNC_INTERVAL;
        self.threads = [threading.Thread(target=self._run_active_chain_sync, daemon=True, name="Smart-Sync")]
        if self.seeder_node_url: self.threads.insert(0, threading.Thread(target=self._run_seeder_bootstrap, daemon=True, name="Seeder-Bootstrap"))
    def start(self):
        for thread in self.threads: thread.start()
    def stop(self): self.is_running = False
    def _broadcast_message(self, endpoint: str, data: dict):
        with self.blockchain.peer_lock: peers_to_broadcast = list(self.blockchain.peers.values())
        for peer in peers_to_broadcast:
            try: requests.post(f"{peer['address']}{endpoint}", json=data, timeout=2)
            except requests.RequestException: continue
    def broadcast_transaction(self, tx: dict): self._broadcast_message('/transactions/add_from_peer', tx)
    def broadcast_block(self, block: Block): self._broadcast_message('/blocks/add_from_peer', block.to_dict())
    def _run_seeder_bootstrap(self):
        self.logger.info(f"[P2P] Cố gắng kết nối đến Seeder tại {self.seeder_node_url}...")
        for _ in range(5):
            if not self.is_running: return
            try:
                response = requests.get(f"{self.seeder_node_url}/get_active_peers", timeout=5)
                if response.status_code == 200:
                    for url in response.json().get("active_nodes", []): self._handshake_and_register(url)
                    self.logger.info(f"✅ [P2P] Hoàn tất bootstrap từ Seeder.")
                    return
            except requests.RequestException: time.sleep(10)
        self.logger.error(f"!!! [P2P] KHÔNG THỂ KẾT NỐI ĐẾN SEEDER {self.seeder_node_url}.")
    def _handshake_and_register(self, base_url: str):
        if not isinstance(base_url, str) or not base_url: return
        try:
            full_url = f"http://{base_url}" if not base_url.startswith(('http://', 'https://')) else base_url
            response = requests.get(f'{full_url}/handshake', timeout=3)
            if response.status_code == 200 and response.json().get('node_id') != self.node_wallet.get_address():
                self.blockchain.register_node(response.json()['node_id'], full_url)
        except requests.RequestException: pass
    def _run_active_chain_sync(self):
        self.logger.info("[Smart Sync] Luồng đồng bộ hóa thông minh đã sẵn sàng.")
        time.sleep(15)
        while self.is_running:
            self.logger.info(f"[Smart Sync] Bắt đầu chu kỳ kiểm tra (Tần suất: {self.sync_interval}s)...")
            try:
                if self.blockchain.resolve_conflicts(): self.sync_interval = FAST_SYNC_INTERVAL
                else: self.sync_interval = NORMAL_SYNC_INTERVAL
            except Exception as e: self.logger.error(f"💥 [Smart Sync] Lỗi: {e}")
            time.sleep(self.sync_interval + random.uniform(1, 5))

# --- ĐIỂM VÀO CHÍNH CỦA CHƯƠNG TRÌNH ---
if __name__ == '__main__':
    # Giai đoạn tương tác với người dùng
    print(Fore.YELLOW + "--- CẤU HÌNH NODE SOKCHAIN (Chế độ Dùng chung Database) ---")
    print(Fore.RED + Style.BRIGHT + "CẢNH BÁO: Chỉ chạy MỘT node tại một thời điểm với file này.")

    print("Nhập mật mã để kích hoạt Seeder Service (ví dụ: AIO), hoặc bỏ trống: ", end='')
    secret_code = input().strip()
    is_seeder_mode = (secret_code == "@10")

    print("Nhập IP/Domain của Seeder Node chính để kết nối (bỏ trống): ", end='')
    seeder_ip = input().strip()
    seeder_connect_url = f"http://{seeder_ip}:5000" if seeder_ip else None
    
    # [THAY ĐỔI] Đặt cổng mặc định là 5000 theo yêu cầu.
    default_port = 5000
    print(f"Nhập cổng để chạy Node này (bỏ trống = {default_port}): ", end='')
    port_str = input().strip()
    try: port = int(port_str) if port_str else default_port
    except ValueError: port = default_port
    
    # Giai đoạn khởi động hệ thống
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] (%(threadName)s) - %(message)s')

    # [GIỮ NGUYÊN] Luôn sử dụng cùng một tên file ví, không phụ thuộc vào port
    wallet_path = os.path.join(project_root, 'node_wallet.pem')
    if not os.path.exists(wallet_path):
        logging.info(f"Không tìm thấy ví node. Đang tạo mới tại '{wallet_path}'...")
        node_wallet = Wallet(); open(wallet_path, 'w', encoding='utf-8').write(node_wallet.get_private_key_pem())
    else:
        node_wallet = Wallet(private_key_pem=open(wallet_path, 'r', encoding='utf-8').read())
    
    genesis_wallet = None

    try: s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('8.8.8.8', 1)); host_ip = s.getsockname()[0]
    except Exception: host_ip = '127.0.0.1'
    finally: s.close()
    
    # [GIỮ NGUYÊN] Luôn sử dụng cùng một tên file database, không phụ thuộc vào port
    db_file_path = os.path.join(project_root, 'blockchain.sqlite')
    logging.info(f"Sử dụng cơ sở dữ liệu dùng chung tại: {db_file_path}")
    blockchain_instance = Blockchain(db_path=db_file_path)

    p2p_manager = P2PManager(blockchain=blockchain_instance, node_wallet=node_wallet, node_port=port, host_ip=host_ip, seeder_node_url=seeder_connect_url)
    app = create_app(blockchain=blockchain_instance, p2p_manager=p2p_manager, node_wallet=node_wallet, genesis_wallet=genesis_wallet)

    seeder_instance = None
    if is_seeder_mode:
        logging.info(Fore.MAGENTA + Style.BRIGHT + "KÍCH HOẠT DỊCH VỤ SEEDER...")
        seeder_instance = SeederService()
        if seeder_instance.is_running:
            @app.route('/get_active_peers', methods=['GET'])
            def get_active_peers_api(): return jsonify({"active_nodes": seeder_instance.get_active_peers()}), 200
            logging.info("✅ Đã thêm endpoint /get_active_peers vào máy chủ API.")
    
    p2p_manager.start()
    
    seeder_status = Fore.GREEN + "[ULTIMATE MODE - ENABLED]" if seeder_instance and seeder_instance.is_running else Fore.RED + "[NORMAL MODE]"
    print("\n" + "=" * 70)
    print(Style.BRIGHT + Fore.CYAN + "      --- Khởi động Node Sokchain v4.0 (Shared DB) ---")
    print("=" * 70); print(f"      Chế độ hoạt động: {seeder_status}")
    if seeder_connect_url: print(f"      Seeder chủ được gán: {seeder_connect_url}")
    else: print("      Seeder chủ: Không gán, sẽ tự khám phá mạng.")
    print(f"      Node ID: {node_wallet.get_address()}"); print(f"      Lắng nghe API tại: http://{host_ip}:{port}")
    print(Fore.YELLOW + Style.BRIGHT + f"      CSDL & Ví DÙNG CHUNG: blockchain.sqlite, node_wallet.pem")
    print(f"      P2P: Smart Sync + Bootstrap (nếu có)"); print("=" * 70)
    
    try:
        serve(app, host='0.0.0.0', port=port, threads=20)
    finally:
        if p2p_manager: p2p_manager.stop()
        if seeder_instance: seeder_instance.stop()
        logging.info("Đã dừng node an toàn.")
