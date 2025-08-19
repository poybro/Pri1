/**
 * Lớp Transaction phía Client để hỗ trợ ký tin nhắn và tạo giao dịch cơ bản.
 * Lớp này sử dụng các thư viện elliptic và js-sha256 đã được nạp toàn cục.
 */
class Transaction {
    /**
     * @param {string | null} senderPublicKey - Public key của người gửi ở định dạng PEM.
     * @param {string | null} recipientAddress - Địa chỉ ví của người nhận.
     * @param {number} amount - Số lượng SOK để chuyển.
     * @param {string | null} senderAddress - Địa chỉ ví của người gửi (tùy chọn).
     */
    constructor(senderPublicKey, recipientAddress, amount, senderAddress = null) {
        this.sender_public_key = senderPublicKey;
        this.recipient_address = recipientAddress;
        this.amount = amount;
        this.sender_address = senderAddress;
        this.timestamp = Date.now();
        // Chữ ký sẽ được thêm sau khi gọi phương thức sign() hoặc signMessage().
        this.signature = null;
    }

    /**
     * Tính toán hash cho một tin nhắn đơn giản.
     * @param {string} message - Tin nhắn cần hash.
     * @returns {string} - Chuỗi hash SHA-256.
     */
    static hashMessage(message) {
        // Giả định rằng thư viện sha256 đã được tải và có sẵn trên phạm vi toàn cục.
        return sha256(message);
    }

    /**
     * Ký một tin nhắn bất kỳ bằng Private Key. Đây là hàm được sử dụng nhiều nhất trong dashboard.
     * @param {string} privateKeyPem - Private key ở định dạng PEM.
     * @param {string} message - Tin nhắn cần ký.
     * @returns {string} - Chữ ký ở định dạng DER (hex).
     */
    signMessage(privateKeyPem, message) {
        try {
            // Giả định thư viện elliptic đã được tải và có sẵn.
            const ec = new elliptic.ec('secp256k1');
            
            // Loại bỏ các dòng header/footer của PEM nếu có, chỉ lấy nội dung Base64.
            const pemBody = privateKeyPem.replace(/-----BEGIN EC PRIVATE KEY-----/g, '')
                                     .replace(/-----END EC PRIVATE KEY-----/g, '')
                                     .replace(/\s/g, '');

            const key = ec.keyFromPrivate(pemBody, 'base64');
            const hash = Transaction.hashMessage(message);
            const signature = key.sign(hash, { canonical: true });
            
            return signature.toDER('hex');
        } catch (error) {
            console.error("Lỗi khi ký tin nhắn:", error);
            alert("Đã có lỗi xảy ra với Private Key của bạn. Vui lòng kiểm tra lại. Lỗi: " + error.message);
            throw error; // Ném lỗi để ngăn các hành động tiếp theo
        }
    }
}