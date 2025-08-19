// static/transaction.js

class Transaction {
    /**
     * @param {string} senderPublicKeyPem - Public key của người gửi (định dạng PEM).
     * @param {string} recipientAddress - Địa chỉ ví người nhận.
     * @param {number} amount - Số lượng SOK.
     * @param {string} senderAddress - Địa chỉ ví người gửi.
     */
    constructor(senderPublicKeyPem, recipientAddress, amount, senderAddress) {
        this.sender_public_key = senderPublicKeyPem;
        this.recipient_address = recipientAddress;
        this.amount = amount;
        this.sender_address = senderAddress;
        this.timestamp = Date.now() / 1000.0; // Sử dụng float timestamp cho nhất quán với Python
        this.tx_hash = this.calculate_hash(); // Tính hash ban đầu
        this.signature = null;
    }

    /**
     * [SỬA LỖI] Tính toán lại hash SHA-256 cho giao dịch một cách nhất quán.
     * @returns {string} - Hash của giao dịch.
     */
    calculate_hash() {
        // Chuyển đổi amount thành chuỗi có 8 chữ số thập phân, giống hệt logic của Python
        const amountStr = Number(this.amount).toFixed(8); 
        
        const data = this.sender_public_key + this.recipient_address + amountStr + this.timestamp;
        return sha256(data);
    }

    /**
     * [SỬA LỖI] Ký vào hash của giao dịch bằng private key.
     * @param {string} privateKeyPem - Khóa bí mật của người gửi ở định dạng PEM thuần túy.
     */
    sign(privateKeyPem) {
        if (!privateKeyPem) {
            throw new Error("Private key is required to sign the transaction.");
        }
        const ec = new elliptic.ec('secp256k1');
        const keyPair = ec.keyFromPrivate(privateKeyPem, 'pem');

        // [SỬA LỖI] Luôn tính toán lại hash ngay trước khi ký để đảm bảo dữ liệu là mới nhất.
        this.tx_hash = this.calculate_hash();

        // Ký vào hash của giao dịch
        const signatureObject = keyPair.sign(this.tx_hash);

        // Chuyển chữ ký sang định dạng DER hex để tương thích với backend Python
        this.signature = signatureObject.toDER('hex');
    }

    /**
     * Chuyển đối tượng giao dịch thành một dictionary thuần túy để gửi đi dưới dạng JSON.
     * @returns {object}
     */
    to_dict() {
        if (!this.signature) {
            throw new Error("Transaction is not signed yet.");
        }
        return {
            sender_public_key: this.sender_public_key,
            sender_address: this.sender_address,
            recipient_address: this.recipient_address,
            amount: this.amount,
            timestamp: this.timestamp,
            tx_hash: this.tx_hash,
            signature: this.signature,
        };
    }
}