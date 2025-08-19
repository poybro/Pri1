// sok_wallet_manager.js

class SokWalletManager {
    constructor(serverUrl) {
        this.SERVER_URL = serverUrl || `http://${window.location.hostname}:9000`;
        this.state = {
            userWallet: null,
            unlockedPrivateKey: null,
        };
        this.loadStateFromStorage();
    }

    // --- Core API Call ---
    async apiRequest(endpoint, method = 'GET', body = null) {
        try {
            const options = { method, headers: { 'Content-Type': 'application/json' } };
            if (body) options.body = JSON.stringify(body);
            const response = await fetch(`${this.SERVER_URL}${endpoint}`, options);
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Lỗi không xác định.');
            return data;
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            alert(`Lỗi giao tiếp server: ${error.message}`);
            throw error;
        }
    }

    // --- State Management ---
    loadStateFromStorage() {
        const savedPK = localStorage.getItem('sok_unlocked_pk_pem');
        if (savedPK) {
            this.unlockWallet(savedPK, false).catch(() => {
                // If unlock fails, clear invalid key
                this.logout();
            });
        }
    }

    saveStateToStorage() {
        if (this.state.unlockedPrivateKey) {
            localStorage.setItem('sok_unlocked_pk_pem', this.state.unlockedPrivateKey);
        } else {
            localStorage.removeItem('sok_unlocked_pk_pem');
        }
    }
    
    // --- Wallet Actions ---
    async createWallet() {
        const data = await this.apiRequest('/api/create_wallet', 'POST');
        this.state.unlockedPrivateKey = data.private_key_pem;
        this.state.userWallet = { address: data.address, public_key_pem: data.public_key_pem };
        this.saveStateToStorage();
        return data; // Return full data for backup modal
    }

    async unlockWallet(privateKeyPem, showSuccessAlert = true) {
        const walletData = await this.apiRequest('/api/wallet_from_pk', 'POST', { private_key_pem: privateKeyPem });
        this.state.userWallet = { address: walletData.address, public_key_pem: walletData.public_key_pem };
        this.state.unlockedPrivateKey = privateKeyPem;
        this.saveStateToStorage();
        if (showSuccessAlert) alert("Ví đã được mở khóa thành công!");
    }

    logout() {
        if (confirm('Bạn có chắc muốn đăng xuất và khóa ví?')) {
            this.state.userWallet = null;
            this.state.unlockedPrivateKey = null;
            this.saveStateToStorage();
            window.location.reload();
        }
    }

    // --- UI Rendering ---
    renderWalletInterface(containerId, onStateChangeCallback) {
        const container = document.getElementById(containerId);
        if (!container) return;

        if (this.state.userWallet) {
            container.innerHTML = `
                <h3><i class="bi bi-wallet-fill"></i> Ví đã Mở khóa</h3>
                <div class="mb-3">
                    <label class="form-label">Địa chỉ:</label>
                    <div class="wallet-info">${this.state.userWallet.address}</div>
                </div>
                <div id="balance-container" class="mb-3">
                    <label class="form-label">Số dư:</label>
                    <div class="wallet-info">Đang tải...</div>
                </div>
                <button class="btn btn-danger w-100" id="logout-btn">
                    <i class="bi bi-lock-fill me-2"></i>Đăng xuất & Khóa Ví
                </button>`;
            this.updateBalance();
            document.getElementById('logout-btn').onclick = () => this.logout();
        } else {
            container.innerHTML = `
                <h3><i class="bi bi-unlock-fill"></i> Mở khóa Ví</h3>
                <button class="btn btn-success w-100 mb-3" id="create-wallet-btn">
                    <i class="bi bi-plus-lg"></i> Tạo Ví Mới
                </button>
                <hr>
                <div class="mb-3">
                    <label for="import-pk-pem" class="form-label"><strong>Hoặc</strong> Dán Private Key để Mở khóa:</label>
                    <textarea id="import-pk-pem" class="form-control" rows="5" placeholder="Private key chỉ được lưu tạm thời trên trình duyệt."></textarea>
                </div>
                <button class="btn btn-primary w-100" id="import-wallet-btn">
                    <i class="bi bi-key-fill"></i> Mở khóa Ví
                </button>`;
            
            document.getElementById('create-wallet-btn').onclick = async () => {
                const walletData = await this.createWallet();
                onStateChangeCallback(walletData); // Pass data to show backup modal
            };
            document.getElementById('import-wallet-btn').onclick = async () => {
                const pkPem = document.getElementById('import-pk-pem').value.trim();
                if (pkPem) await this.unlockWallet(pkPem);
                onStateChangeCallback();
            };
        }
    }

    async updateBalance() {
        const balanceContainer = document.getElementById('balance-container');
        if (!balanceContainer || !this.state.userWallet) return;
        try {
            const data = await this.apiRequest(`/api/get_balance/${this.state.userWallet.address}`);
            balanceContainer.innerHTML = `<label class="form-label">Số dư:</label><div class="wallet-info">${parseFloat(data.balance).toFixed(8)} SOK</div>`;
        } catch (error) {
            balanceContainer.innerHTML = `<label class="form-label">Số dư:</label><div class="wallet-info text-danger">Lỗi</div>`;
        }
    }
}