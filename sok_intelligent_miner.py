#!/usr/bin/env python3
# sok_intelligent_miner.py (Strategic Miner v2.1 - Enhanced Discovery)
# -*- coding: utf-8 -*-

"""
Tác nhân Thợ mỏ Thông minh & Chiến lược (Intelligent & Strategic Miner).

Hành vi:
- Tổng hợp danh sách node từ cả hai nguồn: bản đồ mạng động ('live_network_nodes.json')
  và cấu hình bootstrap tĩnh ('bootstrap_config.json').
- Quét TOÀN BỘ các node đã biết để tìm xem có BẤT KỲ giao dịch nào đang chờ không.
- Nếu phát hiện có việc cần làm (pending tx > 0):
    - Nó sẽ tìm ra node "khỏe" nhất (có chiều cao chuỗi lớn nhất).
    - Nó gửi yêu cầu khai thác đến node khỏe nhất này để tối ưu hóa cơ hội.
- Nếu toàn bộ mạng lưới yên tĩnh, nó sẽ nghỉ một lát rồi mới quét lại.
"""

import os
import sys
import requests
import json
import time
import logging
from typing import List, Optional, Set

# Thêm đường dẫn dự án để có thể import từ 'sok'
project_root = os.path.abspath(os.path.dirname(__file__))
if os.path.join(project_root, 'sok') not in sys.path:
    sys.path.insert(0, project_root)

try:
    from sok.wallet import Wallet
except ImportError as e:
    print(f"[LỖI] Không thể import thư viện 'sok.wallet'. Lỗi: {e}")
    sys.exit(1)

# --- CẤU HÌNH ---
LIVE_NETWORK_CONFIG_FILE = "live_network_nodes.json"
BOOTSTRAP_CONFIG_FILE = "bootstrap_config.json"
MINER_WALLET_FILE = "resilient_miner_wallet.pem"
LOG_FILE = "intelligent_miner.log"
NODE_REQUEST_TIMEOUT = 10

# --- CẤU HÌNH API NODE ---
MEMPOOL_ENDPOINT = "/mempool"
CHAIN_STATS_ENDPOINT = "/chain/stats"

# --- CẤU HÌNH THỜI GIAN ---
FULL_PATROL_DELAY_SECONDS = 10
RETRY_INTERVAL_SECONDS = 30
CRITICAL_ERROR_DELAY_SECONDS = 60

# Cấu hình Logging chi tiết
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [StrategicMiner] [%(levelname)s] - %(message)s',
    encoding='utf-8',
    handlers=[
        logging.FileHandler(LOG_FILE, 'w', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

# === HÀM TÌM KIẾM NODE ĐÃ ĐƯỢC NÂNG CẤP ===
def load_all_known_nodes() -> List[str]:
    """
    Tải và tổng hợp danh sách các node từ tất cả các nguồn đã biết.
    Ưu tiên 'live_network_nodes.json' và dùng 'bootstrap_config.json' làm dự phòng.
    """
    all_nodes: Set[str] = set()

    # Nguồn 1: File bản đồ mạng động (Ưu tiên)
    if os.path.exists(LIVE_NETWORK_CONFIG_FILE):
        try:
            with open(LIVE_NETWORK_CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                live_nodes = data.get("active_nodes", [])
                if live_nodes:
                    logging.info(f"Đã tìm thấy {len(live_nodes)} node từ bản đồ mạng động.")
                    all_nodes.update(live_nodes)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Không thể đọc file bản đồ mạng động: {e}")
    
    # Nguồn 2: File bootstrap tĩnh (Dự phòng)
    if os.path.exists(BOOTSTRAP_CONFIG_FILE):
        try:
            with open(BOOTSTRAP_CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                peers = data.get("trusted_bootstrap_peers", {})
                bootstrap_nodes = [p.get('last_known_address') for p in peers.values() if p.get('last_known_address')]
                if bootstrap_nodes:
                    logging.info(f"Đã tìm thấy {len(bootstrap_nodes)} node từ cấu hình bootstrap.")
                    all_nodes.update(bootstrap_nodes)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Không thể đọc file bootstrap: {e}")

    if not all_nodes:
        logging.error("Không tìm thấy bất kỳ node nào từ cả hai nguồn cấu hình.")

    return list(filter(None, all_nodes))
# ===============================================

class StrategicMiner:
    def __init__(self):
        self.wallet = self._initialize_wallet()

    def _initialize_wallet(self) -> Wallet:
        if not os.path.exists(MINER_WALLET_FILE):
            logging.critical(f"LỖI: Không tìm thấy ví thợ mỏ '{MINER_WALLET_FILE}'.")
            sys.exit(1)
        with open(MINER_WALLET_FILE, 'r', encoding='utf-8') as f:
            return Wallet(private_key_pem=f.read())

    def check_for_work(self, nodes: List[str]) -> bool:
        """Quét các node, trả về True nếu có BẤT KỲ node nào có giao dịch đang chờ."""
        logging.info(f"Đang quét {len(nodes)} node để tìm kiếm công việc...")
        for node_url in nodes:
            try:
                response = requests.get(f'{node_url}{MEMPOOL_ENDPOINT}', timeout=NODE_REQUEST_TIMEOUT)
                if response.status_code == 200 and response.json().get('count', 0) > 0:
                    logging.info(f"🔥 Phát hiện có công việc tại node {node_url}!")
                    return True
            except requests.RequestException:
                logging.debug(f"Không thể kết nối đến {node_url} để kiểm tra công việc.")
            except Exception: pass
        return False

    def find_best_node_to_mine(self, nodes: List[str]) -> Optional[str]:
        """Từ danh sách các node, tìm ra node có chiều cao chuỗi lớn nhất."""
        healthy_nodes = []
        for node_url in nodes:
            try:
                response = requests.get(f'{node_url}{CHAIN_STATS_ENDPOINT}', timeout=NODE_REQUEST_TIMEOUT)
                if response.status_code == 200:
                    stats = response.json()
                    healthy_nodes.append({"url": node_url, "block_height": stats.get('block_height', -1)})
            except requests.RequestException:
                continue
        
        if not healthy_nodes:
            logging.error("Không tìm thấy node nào đang hoạt động để khai thác.")
            return None
            
        best_node = max(healthy_nodes, key=lambda x: x['block_height'])
        logging.info(f"🎯 Đã chọn node tốt nhất để khai thác: {best_node['url']} (Block: {best_node['block_height']})")
        return best_node['url']

    def _mine_on_node(self, node_url: str):
        """Thực hiện một yêu cầu khai thác trên một node duy nhất."""
        try:
            logging.info(f"Bắt đầu yêu cầu khai thác tại {node_url}...")
            response = requests.get(
                f'{node_url}/mine',
                params={'miner_address': self.wallet.get_address()},
                timeout=NODE_REQUEST_TIMEOUT + 5
            )
            if response.status_code == 200:
                data = response.json(); block = data.get('block', {}); block_index = block.get('index', '#?')
                reward_tx = (json.loads(block.get('transactions', '[]')) or [{}])[0]; reward_amount = reward_tx.get('amount', 'N/A')
                logging.info(f"✅ THÀNH CÔNG! Đã khai thác Khối #{block_index} tại {node_url}. Thưởng: {reward_amount} SOK.")
            else:
                logging.warning(f"-> Node {node_url} phản hồi lỗi khi khai thác: {response.status_code} - {response.text[:100]}")
        except requests.exceptions.RequestException:
            logging.warning(f"-> Không thể kết nối hoặc quá thời gian với node {node_url} khi khai thác.")
        except Exception as e:
            logging.error(f"-> Lỗi không xác định khi khai thác tại {node_url}: {e}", exc_info=False)

    def run(self):
        """Vòng lặp chính quản lý việc tuần tra và khai thác chiến lược."""
        logging.info("--- Khởi động Thợ mỏ Thông minh & Chiến lược (v2.1) ---")
        logging.info(f"Địa chỉ Thợ mỏ: {self.wallet.get_address()}")
        
        while True:
            try:
                known_nodes = load_all_known_nodes()
                if not known_nodes:
                    logging.warning(f"Không có node nào để tuần tra. Sẽ thử lại sau {RETRY_INTERVAL_SECONDS} giây...")
                    time.sleep(RETRY_INTERVAL_SECONDS)
                    continue

                if self.check_for_work(known_nodes):
                    best_node = self.find_best_node_to_mine(known_nodes)
                    if best_node:
                        self._mine_on_node(best_node)
                        time.sleep(5) 
                else:
                    logging.info(f"💧 Mạng lưới yên tĩnh. Sẽ quét lại sau {FULL_PATROL_DELAY_SECONDS} giây.")
                    time.sleep(FULL_PATROL_DELAY_SECONDS)
            
            except KeyboardInterrupt:
                logging.info("\nĐã nhận tín hiệu dừng. Thợ mỏ sẽ tắt.")
                break
            except Exception as e:
                logging.error(f"Lỗi nghiêm trọng trong vòng lặp chính: {e}", exc_info=True)
                logging.info(f"Sẽ thử lại sau {CRITICAL_ERROR_DELAY_SECONDS} giây.")
                time.sleep(CRITICAL_ERROR_DELAY_SECONDS)

if __name__ == "__main__":
    miner = StrategicMiner()
    miner.run()
