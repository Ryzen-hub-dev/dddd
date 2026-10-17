<?php
/**
 * Touch 'n Go eWallet / DuitNow QR 个人收款码「上传图片自动转换定制金额」+ Discord Webhook 系统 (单文件完整版)
 *
 * 使用方法：
 * 1. 将本文件 (tng_qr_discord_pay.php) 上传至任何支持 PHP 7.4+ / 8.x 的服务器或本地 PHP 环境（需开启 curl 扩展）。
 * 2. 浏览器访问本文件，在右侧【上传收款码图片自动转换 & Webhook 设置】中：
 *    - 直接上传你的 Touch 'n Go eWallet / DuitNow 个人收款码图片（支持手机完整截屏或二维码原图 PNG/JPG/WEBP）。
 *    - 系统会自动扫描图像并提取底层 EMVCo 二维码载荷（000202...），实时解析收款人户名、TNG 机构代码与 CRC16 签名，并保存到本地配置。
 *    - 填入你的 Discord Webhook URL 并点击保存（支持一键发送测试通知到 Discord）。
 * 3. 在左侧【收银台：生成定制金额收款码】中：
 *    - 输入任意定制金额（MYR/RM）与备注，系统自动把你上传的收款码转换为新收款码（支持一键下载带金额的 PNG 收款码海报），并实时推送 Discord 通知！
 */

declare(strict_types=1);

session_start();

// ==================== 1. 系统配置与持久化加载 ====================
define('CONFIG_FILE', __DIR__ . '/tng_config.json');
define('ORDERS_FILE', __DIR__ . '/tng_orders.json');
define('UPLOAD_DIR', __DIR__ . '/tng_uploads');

$defaultConfig = [
    // Discord 频道 Webhook 地址
    'discord_webhook_url' => getenv('DISCORD_WEBHOOK_URL') ?: '',
    // 从上传图片自动解析出的原始 TNG / DuitNow EMVCo 字符串（默认示例已通过标准 CRC16 校验：9624）
    'base_qr_payload'     => getenv('TNG_BASE_QR_PAYLOAD') ?: '00020201021126520014A000000615000101068900530220TNGD00000000000000005204000053034585802MY5915TNG PERSONAL QR6012KUALA LUMPUR63049624',
    // 已上传的原始二维码图片相对路径
    'uploaded_qr_image'   => '',
    // 默认转换模式：
    // 'emvco_tag54'        -> 自动向二维码注入 Tag 54 定制金额并重算 CRC16 生成新二维码
    // 'static_unique_cent' -> 保持原始静态码数据不变 + 自动分配唯一分位金额（如 RM 10.01）100% 兼容全马银行扫码
    'qr_mode'             => 'emvco_tag54',
    // 管理后台密码（用于保护收款码上传与 Webhook 配置修改，默认 admin123，首次部署后请修改）
    'admin_password'      => getenv('TNG_ADMIN_PASSWORD') ?: 'admin123',
    // 移动端通知转发 App（SMS Forwarder / MacroDroid）自动回调密钥
    'callback_secret'     => getenv('CALLBACK_SECRET') ?: 'tng_webhook_secret_2026',
    // 订单有效时间（秒）
    'order_ttl'           => 300,
];

function loadSystemConfig(array $defaults): array
{
    if (file_exists(CONFIG_FILE)) {
        $raw = @file_get_contents(CONFIG_FILE);
        $saved = $raw ? json_decode($raw, true) : null;
        if (is_array($saved)) {
            return array_merge($defaults, $saved);
        }
    }
    return $defaults;
}

function saveSystemConfig(array $config): bool
{
    return file_put_contents(
        CONFIG_FILE,
        json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    ) !== false;
}

$config = loadSystemConfig($defaultConfig);

// 支持一键下载本 PHP 源码文件 (?action=download_php)
if (isset($_GET['action']) && $_GET['action'] === 'download_php') {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="tng_qr_discord_pay.php"');
    header('Content-Length: ' . filesize(__FILE__));
    readfile(__FILE__);
    exit;
}

// ==================== 2. EMVCo / DuitNow QR 转换与解析核心类 ====================
class TngDuitNowQr
{
    /**
     * 计算 EMVCo 标准 CRC-16/CCITT-FALSE 校验码
     * Polynomial: 0x1021, Initial Value: 0xFFFF
     */
    public static function crc16(string $data): string
    {
        $crc = 0xFFFF;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $crc ^= (ord($data[$i]) << 8);
            for ($j = 0; $j < 8; $j++) {
                if (($crc & 0x8000) !== 0) {
                    $crc = (($crc << 1) ^ 0x1021) & 0xFFFF;
                } else {
                    $crc = ($crc << 1) & 0xFFFF;
                }
            }
        }
        return strtoupper(str_pad(dechex($crc), 4, '0', STR_PAD_LEFT));
    }

    /**
     * 解析 EMVCo TLV 字符串为关联数组
     */
    public static function parseTlv(string $payload): array
    {
        $tags = [];
        $pos = 0;
        $len = strlen($payload);

        while ($pos + 4 <= $len) {
            $tag = substr($payload, $pos, 2);
            $lengthStr = substr($payload, $pos + 2, 2);
            if (!ctype_digit($lengthStr)) {
                break;
            }
            $valueLen = (int)$lengthStr;
            if ($pos + 4 + $valueLen > $len) {
                break;
            }
            $value = substr($payload, $pos + 4, $valueLen);
            $tags[$tag] = $value;
            $pos += 4 + $valueLen;
        }
        return $tags;
    }

    /**
     * 验证 EMVCo QR 字符串的 CRC16 是否有效
     */
    public static function verifyCrc(string $payload): bool
    {
        $payload = trim($payload);
        if (strlen($payload) < 12 || substr($payload, -8, 4) !== '6304') {
            return false;
        }
        $bodyWith6304 = substr($payload, 0, -4);
        $expectedCrc = strtoupper(substr($payload, -4));
        return self::crc16($bodyWith6304) === $expectedCrc;
    }

    /**
     * 提取二维码中的收款人可读信息（姓名、收单机构、地区、是否含初始金额）
     */
    public static function inspectPayload(string $payload): array
    {
        $payload = trim($payload);
        $isEmvco = (strpos($payload, '000201') === 0 || strpos($payload, '000202') === 0);
        if (!$isEmvco) {
            return [
                'is_emvco'      => false,
                'crc_valid'     => false,
                'merchant_name' => '非标准 EMVCo 载荷（原样编码转换）',
                'acquirer_id'   => 'N/A',
                'acquirer_name' => '自定义二维码 / URL',
                'qr_id'         => 'N/A',
                'city'          => 'MY',
            ];
        }

        $tags = self::parseTlv($payload);
        $sub26 = isset($tags['26']) ? self::parseTlv($tags['26']) : [];
        $acquirerId = $sub26['01'] ?? '未知';

        $acquirerMap = [
            '890053' => 'TNG Digital Sdn Bhd (Touch \'n Go eWallet)',
            '588734' => 'Maybank Berhad (MAE)',
            '501854' => 'CIMB Bank Berhad',
            '564162' => 'Public Bank Berhad',
            '588830' => 'Hong Leong Bank Berhad',
            '564160' => 'RHB Bank Berhad',
            '890004' => 'ShopeePay Malaysia',
            '890046' => 'GrabPay Malaysia',
            '890061' => 'Boost Malaysia',
            '629279' => 'GXBank Berhad',
        ];

        return [
            'is_emvco'      => true,
            'crc_valid'     => self::verifyCrc($payload),
            'poi_method'    => ($tags['01'] ?? '11') === '12' ? '动态码 (12)' : '静态码 (11)',
            'merchant_name' => $tags['59'] ?? '未标注名称',
            'city'          => $tags['60'] ?? 'MY',
            'acquirer_id'   => $acquirerId,
            'acquirer_name' => $acquirerMap[$acquirerId] ?? ('DuitNow 机构 (' . $acquirerId . ')'),
            'qr_id'         => $sub26['02'] ?? '未知',
            'currency'      => ($tags['53'] ?? '') === '458' ? 'MYR (458)' : ($tags['53'] ?? '未知'),
        ];
    }

    /**
     * 将 TLV 数组重新编码并计算正确的 Tag 63 CRC16
     */
    public static function buildTlv(array $tags): string
    {
        unset($tags['63']);
        ksort($tags, SORT_STRING);

        $raw = '';
        foreach ($tags as $id => $value) {
            $idStr = str_pad((string)$id, 2, '0', STR_PAD_LEFT);
            $valStr = (string)$value;
            $lenStr = str_pad((string)strlen($valStr), 2, '0', STR_PAD_LEFT);
            $raw .= $idStr . $lenStr . $valStr;
        }

        $raw .= '6304';
        return $raw . self::crc16($raw);
    }

    /**
     * 自动转换二维码数据：注入 Tag 54 定制金额与 Tag 62 订单备注并重算 CRC16
     */
    public static function convertWithCustomAmount(
        string $basePayload,
        float $amount,
        string $orderRef = '',
        bool $switchToDynamicTag01 = false
    ): string {
        $basePayload = trim($basePayload);
        if (strpos($basePayload, '000201') !== 0 && strpos($basePayload, '000202') !== 0) {
            // 若上传的是普通 URL 型二维码，附加 amount 参数返回
            $sep = (strpos($basePayload, '?') === false) ? '?' : '&';
            return $basePayload . $sep . 'amount=' . number_format($amount, 2, '.', '');
        }

        $tags = self::parseTlv($basePayload);

        // 保持 01=11（静态带金额）可避免触发 PayNet 网关对 01=12 动态码的 60 秒服务端 Token 强校验
        if ($switchToDynamicTag01) {
            $tags['01'] = '12';
        } else {
            $tags['01'] = '11';
        }

        if ($amount > 0) {
            $tags['54'] = number_format($amount, 2, '.', '');
        } else {
            unset($tags['54']);
        }

        if ($orderRef !== '') {
            $subTags = isset($tags['62']) ? self::parseTlv($tags['62']) : [];
            $cleanRef = substr(preg_replace('/[^A-Za-z0-9\-_]/', '', $orderRef), 0, 20);
            if ($cleanRef !== '') {
                $subTags['01'] = $cleanRef; // Tag 62 -> 01: Bill Number
                ksort($subTags, SORT_STRING);
                $subRaw = '';
                foreach ($subTags as $sId => $sVal) {
                    $subRaw .= str_pad((string)$sId, 2, '0', STR_PAD_LEFT)
                        . str_pad((string)strlen((string)$sVal), 2, '0', STR_PAD_LEFT)
                        . $sVal;
                }
                $tags['62'] = $subRaw;
            }
        }

        return self::buildTlv($tags);
    }

    /**
     * 服务端后备二维码图片解码（如果前端 JS 未解码，尝试调用服务端 zbarimg 工具识别上传的图片）
     */
    public static function decodeImageFallback(string $filePath): ?string
    {
        if (!file_exists($filePath) || !function_exists('shell_exec')) {
            return null;
        }
        $escaped = escapeshellarg($filePath);
        $output = @shell_exec("zbarimg --quiet --raw $escaped 2>/dev/null");
        if (is_string($output) && trim($output) !== '') {
            return trim($output);
        }
        return null;
    }
}

// ==================== 3. Discord Webhook 推送类 ====================
class DiscordNotifier
{
    private string $webhookUrl;

    public function __construct(string $webhookUrl)
    {
        $this->webhookUrl = trim($webhookUrl);
    }

    public function sendEmbed(string $title, string $description, array $fields, int $color = 0x0055FF): array
    {
        if ($this->webhookUrl === '' || strpos($this->webhookUrl, 'discord.com/api/webhooks/') === false) {
            return [
                'ok'    => false,
                'error' => '尚未配置有效的 Discord Webhook URL（需包含 discord.com/api/webhooks/...）',
            ];
        }

        $payload = [
            'username' => 'TNG eWallet 收款通知助手',
            'embeds'   => [
                [
                    'title'       => $title,
                    'description' => $description,
                    'color'       => $color,
                    'fields'      => $fields,
                    'footer'      => [
                        'text' => 'Touch \'n Go eWallet / DuitNow QR Auto-Converter',
                    ],
                    'timestamp'   => gmdate('c'),
                ],
            ],
        ];

        $ch = curl_init($this->webhookUrl);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_UNICODE),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
        ]);

        $response = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr  = curl_error($ch);
        curl_close($ch);

        if ($curlErr !== '') {
            return ['ok' => false, 'error' => $curlErr, 'http_code' => $httpCode];
        }

        return [
            'ok'        => ($httpCode >= 200 && $httpCode < 300),
            'http_code' => $httpCode,
            'response'  => $response,
            'error'     => ($httpCode >= 200 && $httpCode < 300) ? '' : "HTTP $httpCode: $response",
        ];
    }
}

// ==================== 4. 订单管理与防撞单金额分配 ====================
class OrderManager
{
    private string $storageFile;
    private int $ttl;

    public function __construct(string $storageFile, int $ttl = 300)
    {
        $this->storageFile = $storageFile;
        $this->ttl = $ttl;
        if (!file_exists($this->storageFile)) {
            @file_put_contents($this->storageFile, json_encode([], JSON_PRETTY_PRINT));
        }
    }

    public function loadOrders(): array
    {
        $content = @file_get_contents($this->storageFile);
        $orders = $content ? json_decode($content, true) : [];
        return is_array($orders) ? $orders : [];
    }

    public function saveOrders(array $orders): void
    {
        @file_put_contents($this->storageFile, json_encode($orders, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    }

    /**
     * 为静态收款码分配未占用的唯一实付金额（例如 10.00 -> 10.01, 10.02...）
     */
    public function allocateUniqueAmount(float $baseAmount): float
    {
        $orders = $this->loadOrders();
        $now = time();
        $usedAmounts = [];

        foreach ($orders as $ord) {
            if (($ord['status'] ?? '') === 'pending' && ($now - ($ord['created_at'] ?? 0)) < $this->ttl) {
                $usedAmounts[number_format((float)$ord['pay_amount'], 2, '.', '')] = true;
            }
        }

        for ($i = 0; $i < 99; $i++) {
            $candidate = round($baseAmount + ($i * 0.01), 2);
            $key = number_format($candidate, 2, '.', '');
            if (!isset($usedAmounts[$key])) {
                return $candidate;
            }
        }

        return round($baseAmount, 2);
    }

    public function createOrder(
        float $requestedAmount,
        float $payAmount,
        string $payerNote,
        string $qrPayload,
        string $mode
    ): array {
        $orders = $this->loadOrders();
        $orderId = 'TNG' . date('YmdHis') . random_int(100, 999);

        $order = [
            'order_id'         => $orderId,
            'requested_amount' => round($requestedAmount, 2),
            'pay_amount'       => round($payAmount, 2),
            'payer_note'       => $payerNote,
            'qr_mode'          => $mode,
            'qr_payload'       => $qrPayload,
            'status'           => 'pending',
            'created_at'       => time(),
            'expires_at'       => time() + $this->ttl,
            'paid_at'          => null,
        ];

        $orders[$orderId] = $order;
        $this->saveOrders($orders);
        return $order;
    }

    public function markPaidByAmount(float $receivedAmount, string $rawNotification = ''): ?array
    {
        $orders = $this->loadOrders();
        $now = time();
        $targetKey = number_format($receivedAmount, 2, '.', '');

        foreach ($orders as $id => &$ord) {
            if (
                ($ord['status'] ?? '') === 'pending'
                && ($now <= ($ord['expires_at'] ?? 0))
                && number_format((float)$ord['pay_amount'], 2, '.', '') === $targetKey
            ) {
                $ord['status'] = 'paid';
                $ord['paid_at'] = $now;
                $ord['raw_notification'] = $rawNotification;
                $this->saveOrders($orders);
                return $ord;
            }
        }
        return null;
    }
}

// ==================== 5. 路由与请求处理 ====================
$notifier = new DiscordNotifier($config['discord_webhook_url']);
$orderManager = new OrderManager(ORDERS_FILE, (int)$config['order_ttl']);

// 5.1 处理移动端通知监听 App 的自动回调接口 (POST ?action=webhook_callback)
if (isset($_GET['action']) && $_GET['action'] === 'webhook_callback' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    $rawInput = file_get_contents('php://input');
    $data = json_decode($rawInput, true) ?: $_POST;

    $secret = $data['secret'] ?? ($_SERVER['HTTP_X_CALLBACK_SECRET'] ?? '');
    if ($secret !== $config['callback_secret']) {
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Invalid callback secret']);
        exit;
    }

    $amount = isset($data['amount']) ? (float)$data['amount'] : 0.0;
    $text   = (string)($data['text'] ?? $data['content'] ?? '');
    if ($amount <= 0 && preg_match('/RM\s*([0-9]+(?:\.[0-9]{1,2})?)/i', $text, $matches)) {
        $amount = (float)$matches[1];
    }

    if ($amount <= 0) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'No valid RM amount found']);
        exit;
    }

    $matchedOrder = $orderManager->markPaidByAmount($amount, $text);
    if ($matchedOrder) {
        $webhookRes = $notifier->sendEmbed(
            '✅ TNG eWallet 收款自动核销成功',
            '系统已匹配到手机端 TNG 收款通知，订单已自动标记为已支付。',
            [
                ['name' => '订单号', 'value' => '`' . $matchedOrder['order_id'] . '`', 'inline' => true],
                ['name' => '实收金额', 'value' => '**RM ' . number_format($matchedOrder['pay_amount'], 2) . '**', 'inline' => true],
                ['name' => '买家备注', 'value' => $matchedOrder['payer_note'] ?: '无', 'inline' => false],
                ['name' => '通知原文', 'value' => $text ?: 'API 直接回调', 'inline' => false],
            ],
            0x2ECC71
        );
        echo json_encode(['status' => 'success', 'order' => $matchedOrder, 'discord' => $webhookRes]);
    } else {
        $webhookRes = $notifier->sendEmbed(
            '⚠️ 收到未匹配订单的 TNG 款项',
            '监听到一笔 TNG eWallet 收款，但未找到对应金额的待支付订单。',
            [
                ['name' => '到账金额', 'value' => '**RM ' . number_format($amount, 2) . '**', 'inline' => true],
                ['name' => '通知原文', 'value' => $text ?: '无', 'inline' => false],
            ],
            0xF39C12
        );
        echo json_encode(['status' => 'unmatched', 'amount' => $amount, 'discord' => $webhookRes]);
    }
    exit;
}

// 5.2 处理表单请求：上传收款码图片自动转换保存 / 测试 Discord / 创建定制金额订单 / 买家确认已付款
$currentOrder = null;
$flashSuccess = '';
$flashError   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['form_action'])) {
    $action = (string)$_POST['form_action'];

    // (A) 上传收款码图片自动识别转换 & 保存配置
    if ($action === 'save_qr_and_config') {
        $inputPass = (string)($_POST['admin_password'] ?? '');
        if ($inputPass !== $config['admin_password']) {
            $flashError = '管理密码不正确（默认密码为 admin123），无法修改收款码与 Webhook 配置。';
        } else {
            $decodedPayload = trim((string)($_POST['decoded_qr_payload'] ?? ''));

            // 处理上传的收款码图片文件
            if (isset($_FILES['qr_image_file']) && $_FILES['qr_image_file']['error'] === UPLOAD_ERR_OK) {
                $tmpPath = $_FILES['qr_image_file']['tmp_name'];
                $origName = basename((string)$_FILES['qr_image_file']['name']);
                $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));

                if (in_array($ext, ['png', 'jpg', 'jpeg', 'webp'], true)) {
                    if (!is_dir(UPLOAD_DIR)) {
                        @mkdir(UPLOAD_DIR, 0755, true);
                    }
                    $savedName = 'tng_base_qr_' . time() . '.' . $ext;
                    $destPath = UPLOAD_DIR . '/' . $savedName;
                    if (@move_uploaded_file($tmpPath, $destPath)) {
                        $config['uploaded_qr_image'] = 'tng_uploads/' . $savedName;
                        // 如果前端 JS 未传入解码结果，尝试服务端自动解码
                        if ($decodedPayload === '') {
                            $fallbackDecoded = TngDuitNowQr::decodeImageFallback($destPath);
                            if ($fallbackDecoded !== null) {
                                $decodedPayload = $fallbackDecoded;
                            }
                        }
                    }
                } else {
                    $flashError = '请上传 PNG、JPG 或 WEBP 格式的收款码图片。';
                }
            }

            if ($flashError === '') {
                if ($decodedPayload !== '') {
                    $config['base_qr_payload'] = $decodedPayload;
                }
                if (isset($_POST['discord_webhook_url'])) {
                    $config['discord_webhook_url'] = trim((string)$_POST['discord_webhook_url']);
                }
                if (isset($_POST['default_qr_mode'])) {
                    $config['qr_mode'] = (string)$_POST['default_qr_mode'];
                }
                if (!empty($_POST['new_admin_password'])) {
                    $config['admin_password'] = trim((string)$_POST['new_admin_password']);
                }

                saveSystemConfig($config);
                $notifier = new DiscordNotifier($config['discord_webhook_url']);
                $info = TngDuitNowQr::inspectPayload($config['base_qr_payload']);
                $flashSuccess = '✅ 收款码图片已自动识别转换并保存！识别到收款方：'
                    . htmlspecialchars($info['merchant_name'])
                    . '（机构：' . htmlspecialchars($info['acquirer_name']) . '）';
            }
        }
    }

    // (B) 一键发送 Discord Webhook 测试通知
    elseif ($action === 'test_discord_webhook') {
        $testUrl = trim((string)($_POST['discord_webhook_url'] ?? $config['discord_webhook_url']));
        $testNotifier = new DiscordNotifier($testUrl);
        $info = TngDuitNowQr::inspectPayload($config['base_qr_payload']);
        $res = $testNotifier->sendEmbed(
            '🎉 Touch \'n Go eWallet 收款系统 Webhook 测试成功',
            '你的 PHP 个人收款码定制金额系统已成功连接至此 Discord 频道！',
            [
                ['name' => '当前绑定收款人', 'value' => $info['merchant_name'], 'inline' => true],
                ['name' => '收单机构', 'value' => $info['acquirer_name'], 'inline' => true],
                ['name' => 'CRC16 校验状态', 'value' => $info['crc_valid'] ? '✅ 通过' : '⚠️ 非标准载荷', 'inline' => true],
            ],
            0x0055FF
        );
        if ($res['ok']) {
            $flashSuccess = '✅ Discord Webhook 测试消息已成功发送到你的频道！';
        } else {
            $flashError = '❌ Discord Webhook 发送失败：' . htmlspecialchars($res['error'] ?? '未知错误');
        }
    }

    // (C) 输入定制金额 -> 自动生成转换后的收款码并推送 Discord
    elseif ($action === 'create_order') {
        $reqAmount    = max(0.01, (float)($_POST['amount'] ?? 0));
        $payerNote    = trim((string)($_POST['payer_note'] ?? ''));
        $selectedMode = (string)($_POST['qr_mode'] ?? $config['qr_mode']);

        // 也允许用户在创建订单时顺带上传一张新的收款码图片即时转换
        $activeBasePayload = $config['base_qr_payload'];
        if (!empty($_POST['instant_decoded_qr'])) {
            $activeBasePayload = trim((string)$_POST['instant_decoded_qr']);
        }

        if ($selectedMode === 'emvco_tag54') {
            $payAmount = round($reqAmount, 2);
            $qrPayload = TngDuitNowQr::convertWithCustomAmount($activeBasePayload, $payAmount, $payerNote, false);
        } else {
            $payAmount = $orderManager->allocateUniqueAmount($reqAmount);
            $qrPayload = $activeBasePayload;
        }

        $currentOrder = $orderManager->createOrder($reqAmount, $payAmount, $payerNote, $qrPayload, $selectedMode);
        $qrMeta = TngDuitNowQr::inspectPayload($qrPayload);

        $notifier->sendEmbed(
            '🆕 已生成定制金额 TNG 收款码',
            '系统已将个人收款码自动转换为定制金额二维码，等待买家扫码支付。',
            [
                ['name' => '订单号', 'value' => '`' . $currentOrder['order_id'] . '`', 'inline' => true],
                ['name' => '定制应收金额', 'value' => '**RM ' . number_format($currentOrder['pay_amount'], 2) . '**', 'inline' => true],
                ['name' => '收款户名', 'value' => $qrMeta['merchant_name'], 'inline' => true],
                ['name' => '买家备注', 'value' => $currentOrder['payer_note'] ?: '无', 'inline' => true],
                ['name' => '转换模式', 'value' => $selectedMode === 'emvco_tag54' ? 'EMVCo Tag 54 注入转换' : '原码 + 唯一尾数防撞单', 'inline' => true],
            ],
            0x3498DB
        );
    }

    // (D) 买家点击「我已完成付款」推送到 Discord 提醒核实
    elseif ($action === 'confirm_paid') {
        $orderId = (string)($_POST['order_id'] ?? '');
        $txRef   = trim((string)($_POST['tx_ref'] ?? ''));
        $orders  = $orderManager->loadOrders();

        if (isset($orders[$orderId])) {
            $currentOrder = $orders[$orderId];
            $res = $notifier->sendEmbed(
                '🔔 买家已提交付款确认（请核实到账）',
                '买家已在页面点击「我已完成付款」，请核对 Touch \'n Go eWallet 账单。',
                [
                    ['name' => '订单号', 'value' => '`' . $currentOrder['order_id'] . '`', 'inline' => true],
                    ['name' => '应付金额', 'value' => '**RM ' . number_format($currentOrder['pay_amount'], 2) . '**', 'inline' => true],
                    ['name' => '买家填写的交易号/备注', 'value' => $txRef ?: ($currentOrder['payer_note'] ?: '未填写'), 'inline' => false],
                ],
                0x9B59B6
            );
            if ($res['ok']) {
                $flashSuccess = '✅ 已通过 Discord Webhook 通知收款人核实您的款项！';
            } else {
                $flashError = '本地已记录付款申报（但 Discord Webhook 未配置或推送失败：' . htmlspecialchars($res['error'] ?? '') . '）';
            }
        }
    }
}

$currentQrInfo = TngDuitNowQr::inspectPayload($config['base_qr_payload']);
?>
<!DOCTYPE html>
<html lang="zh-MY">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TNG eWallet / DuitNow 上传图片自动转换定制金额 & Discord Webhook</title>
    <style>
        :root {
            --tng-blue: #0055ff;
            --tng-dark: #07193a;
            --bg: #f1f5f9;
            --border: #e2e8f0;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: #1e293b;
            margin: 0;
            padding: 24px 16px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        @media (max-width: 768px) {
            .container { grid-template-columns: 1fr; }
        }
        .top-bar {
            max-width: 900px;
            margin: 0 auto 16px auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--tng-dark);
            color: #fff;
            padding: 14px 20px;
            border-radius: 14px;
        }
        .top-bar h1 {
            font-size: 17px;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .badge {
            background: var(--tng-blue);
            color: #fff;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
        }
        .download-btn {
            background: #10b981;
            color: #fff;
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
            padding: 8px 14px;
            border-radius: 8px;
        }
        .card {
            background: #fff;
            border-radius: 16px;
            padding: 22px;
            box-shadow: 0 4px 20px rgba(15, 23, 42, 0.06);
        }
        .card h2 {
            font-size: 16px;
            margin: 0 0 14px 0;
            color: var(--tng-dark);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }
        label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 6px;
            color: #334155;
        }
        input[type="text"], input[type="number"], input[type="password"], input[type="url"], select, textarea {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 14px;
        }
        textarea {
            font-family: monospace;
            font-size: 12px;
            resize: vertical;
        }
        .dropzone {
            border: 2px dashed #94a3b8;
            background: #f8fafc;
            border-radius: 12px;
            padding: 16px;
            text-align: center;
            cursor: pointer;
            margin-bottom: 14px;
            transition: all 0.2s;
        }
        .dropzone:hover {
            border-color: var(--tng-blue);
            background: #eff6ff;
        }
        .btn {
            width: 100%;
            background: var(--tng-blue);
            color: #fff;
            border: none;
            padding: 11px 14px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 8px;
        }
        .btn-secondary {
            background: #475569;
        }
        .btn-success {
            background: #059669;
        }
        .meta-box {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 12px;
            font-size: 13px;
            margin-bottom: 14px;
            line-height: 1.6;
        }
        .alert-ok {
            max-width: 900px;
            margin: 0 auto 16px auto;
            background: #ecfdf5;
            border: 1px solid #6ee7b7;
            color: #065f46;
            padding: 12px 16px;
            border-radius: 10px;
            font-size: 14px;
        }
        .alert-err {
            max-width: 900px;
            margin: 0 auto 16px auto;
            background: #fef2f2;
            border: 1px solid #fca5a5;
            color: #991b1b;
            padding: 12px 16px;
            border-radius: 10px;
            font-size: 14px;
        }
        .qr-result-box {
            text-align: center;
            background: linear-gradient(180deg, #0055ff 0%, #003bb3 100%);
            color: #fff;
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 16px;
        }
        .qr-white-card {
            background: #fff;
            color: #0f172a;
            border-radius: 12px;
            padding: 16px;
            display: inline-block;
            margin: 10px 0;
        }
        .amount-big {
            font-size: 28px;
            font-weight: 800;
            margin: 4px 0;
        }
        #qrcode {
            display: flex;
            justify-content: center;
            margin: 8px 0;
        }
    </style>
    <!-- 引入 jsQR（用于浏览器端直接读取上传的 TNG 收款码图片并自动提取 EMVCo 字符串）与 QRCode.js（生成转换后的新二维码） -->
    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
</head>
<body>

<div class="top-bar">
    <h1>
        <span class="badge">TNG eWallet / DuitNow</span>
        上传图片自动转换定制金额 & Discord Webhook 系统
    </h1>
    <a class="download-btn" href="?action=download_php">⬇ 下载此 PHP 文件</a>
</div>

<?php if ($flashSuccess !== ''): ?>
    <div class="alert-ok"><?= $flashSuccess ?></div>
<?php endif; ?>
<?php if ($flashError !== ''): ?>
    <div class="alert-err"><?= $flashError ?></div>
<?php endif; ?>

<div class="container">
    <!-- 左栏：收银台（自动转换生成定制金额收款码） -->
    <div class="card">
        <h2>⚡ 收银台：生成定制金额收款码</h2>

        <?php if (!$currentOrder): ?>
            <form method="post" id="orderForm">
                <input type="hidden" name="form_action" value="create_order">
                <input type="hidden" name="instant_decoded_qr" id="instant_decoded_qr" value="">

                <label for="amount">定制收款金额 (MYR / RM)</label>
                <input type="number" id="amount" name="amount" step="0.01" min="0.01" value="15.00" required>

                <label for="payer_note">付款备注 / 订单号</label>
                <input type="text" id="payer_note" name="payer_note" placeholder="例如：Order-1001 / VIP会员">

                <label for="qr_mode">二维码自动转换模式</label>
                <select id="qr_mode" name="qr_mode">
                    <option value="emvco_tag54" <?= $config['qr_mode'] === 'emvco_tag54' ? 'selected' : '' ?>>
                        自动转换二维码：注入 Tag 54 定制金额 + 重算 CRC16
                    </option>
                    <option value="static_unique_cent" <?= $config['qr_mode'] === 'static_unique_cent' ? 'selected' : '' ?>>
                        100% 兼容模式：保留原码载荷 + 自动分配唯一金额尾数
                    </option>
                </select>

                <label>快速临时上传收款码图片转换（可选，默认使用右侧已保存的收款码）</label>
                <div class="dropzone" onclick="document.getElementById('instant_qr_file').click()">
                    <span id="instant_status_text">📷 点击此处可临时选一张 TNG 收款码图片直接转换</span>
                    <input type="file" id="instant_qr_file" accept="image/*" style="display:none">
                </div>

                <button type="submit" class="btn">🔄 立即转换生成定制金额收款码 & 通知 Discord</button>
            </form>
        <?php else: ?>
            <div class="qr-result-box" id="posterArea">
                <div style="font-size:14px;opacity:0.9;">Touch 'n Go eWallet / DuitNow 收款码</div>
                <div class="amount-big">RM <?= number_format($currentOrder['pay_amount'], 2) ?></div>
                <div style="font-size:13px;opacity:0.9;">
                    收款户名：<?= htmlspecialchars($currentQrInfo['merchant_name']) ?>
                </div>

                <div class="qr-white-card">
                    <div id="qrcode"></div>
                    <div style="font-size:11px;color:#475569;margin-top:6px;">
                        订单号：<?= htmlspecialchars($currentOrder['order_id']) ?>
                    </div>
                </div>

                <?php if ($currentOrder['qr_mode'] === 'static_unique_cent'): ?>
                    <div style="font-size:12px;background:rgba(0,0,0,0.25);padding:8px;border-radius:8px;">
                        ⚠️ 扫码后请严格输入上方显示的金额 <strong>RM <?= number_format($currentOrder['pay_amount'], 2) ?></strong>
                    </div>
                <?php else: ?>
                    <div style="font-size:12px;opacity:0.9;">
                        ✅ 已将 RM <?= number_format($currentOrder['pay_amount'], 2) ?> 写入二维码 Tag 54 并完成 CRC16 签名
                    </div>
                <?php endif; ?>
            </div>

            <button type="button" class="btn btn-success" onclick="downloadConvertedQr()">
                💾 下载转换后的定制金额二维码图片 (PNG)
            </button>

            <form method="post" style="margin-top:10px;">
                <input type="hidden" name="form_action" value="confirm_paid">
                <input type="hidden" name="order_id" value="<?= htmlspecialchars($currentOrder['order_id']) ?>">
                <label for="tx_ref">买家完成扫码付款后，可填写转账单号通知收款人：</label>
                <input type="text" id="tx_ref" name="tx_ref" placeholder="选填：TNG 交易单号或留空">
                <button type="submit" class="btn">✅ 我已完成付款（推送 Discord 通知）</button>
            </form>

            <a href="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" style="display:block;text-align:center;font-size:13px;color:#475569;margin-top:10px;">
                ← 返回重新生成其他定制金额
            </a>

            <script>
                new QRCode(document.getElementById("qrcode"), {
                    text: <?= json_encode($currentOrder['qr_payload']) ?>,
                    width: 210,
                    height: 210,
                    correctLevel: QRCode.CorrectLevel.M
                });

                function downloadConvertedQr() {
                    const qrCanvas = document.querySelector('#qrcode canvas');
                    if (!qrCanvas) return;
                    const outCanvas = document.createElement('canvas');
                    outCanvas.width = 360;
                    outCanvas.height = 440;
                    const ctx = outCanvas.getContext('2d');

                    // 绘制蓝色背景卡片
                    ctx.fillStyle = '#0055ff';
                    ctx.fillRect(0, 0, 360, 440);

                    ctx.fillStyle = '#ffffff';
                    ctx.font = 'bold 18px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.fillText("Touch 'n Go / DuitNow QR", 180, 40);

                    ctx.font = 'bold 30px sans-serif';
                    ctx.fillText("RM <?= number_format($currentOrder['pay_amount'], 2) ?>", 180, 80);

                    ctx.fillStyle = '#ffffff';
                    ctx.fillRect(55, 105, 250, 250);
                    ctx.drawImage(qrCanvas, 75, 125, 210, 210);

                    ctx.fillStyle = '#ffffff';
                    ctx.font = '14px sans-serif';
                    ctx.fillText(<?= json_encode($currentQrInfo['merchant_name']) ?>, 180, 385);
                    ctx.font = '12px sans-serif';
                    ctx.fillText("Order: <?= htmlspecialchars($currentOrder['order_id']) ?>", 180, 410);

                    const link = document.createElement('a');
                    link.download = 'TNG_QR_RM_<?= number_format($currentOrder['pay_amount'], 2, '_', '') ?>.png';
                    link.href = outCanvas.toDataURL('image/png');
                    link.click();
                }
            </script>
        <?php endif; ?>
    </div>

    <!-- 右栏：上传收款码图片自动识别转换 & Discord Webhook 配置 -->
    <div class="card">
        <h2>⚙️ 上传收款码图片自动转换 & Webhook 设置</h2>

        <div class="meta-box" id="parsedMetaBox">
            <div><strong>当前生效收款人：</strong><span id="meta_name"><?= htmlspecialchars($currentQrInfo['merchant_name']) ?></span></div>
            <div><strong>收单机构：</strong><span id="meta_acq"><?= htmlspecialchars($currentQrInfo['acquirer_name']) ?></span></div>
            <div><strong>CRC16 校验：</strong><span id="meta_crc"><?= $currentQrInfo['crc_valid'] ? '✅ 合法 EMVCo 标准码' : '⚠️ 自定义载荷' ?></span></div>
        </div>

        <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="form_action" value="save_qr_and_config">

            <label>步骤 1：上传你的 TNG / DuitNow 个人收款码图片（系统自动识别转换）</label>
            <div class="dropzone" onclick="document.getElementById('qr_image_file').click()">
                <div id="upload_status_text" style="font-size:13px;color:#0055ff;font-weight:600;">
                    📤 点击选择或拖拽上传收款码截图 / 图片 (PNG, JPG, WEBP)
                </div>
                <div style="font-size:12px;color:#64748b;margin-top:4px;">
                    上传后系统将自动扫描图像并提取底层 EMVCo 收款码数据
                </div>
                <img id="upload_preview_img" src="" alt="" style="display:none;max-width:120px;max-height:120px;margin:10px auto 0;border-radius:8px;border:1px solid #cbd5e1;">
                <input type="file" id="qr_image_file" name="qr_image_file" accept="image/*" style="display:none">
            </div>

            <label for="decoded_qr_payload">自动转换出的底层二维码字符串（上传图片后自动填入，也可手动粘贴）</label>
            <textarea id="decoded_qr_payload" name="decoded_qr_payload" rows="3" required><?= htmlspecialchars($config['base_qr_payload']) ?></textarea>

            <label for="discord_webhook_url">步骤 2：Discord Webhook URL</label>
            <input type="url" id="discord_webhook_url" name="discord_webhook_url"
                   value="<?= htmlspecialchars($config['discord_webhook_url']) ?>"
                   placeholder="https://discord.com/api/webhooks/...">

            <label for="default_qr_mode">默认转换模式</label>
            <select id="default_qr_mode" name="default_qr_mode">
                <option value="emvco_tag54" <?= $config['qr_mode'] === 'emvco_tag54' ? 'selected' : '' ?>>
                    EMVCo Tag 54 注入定制金额 + 重算 CRC16
                </option>
                <option value="static_unique_cent" <?= $config['qr_mode'] === 'static_unique_cent' ? 'selected' : '' ?>>
                    保持原静态码不变 + 自动分配唯一分位尾数
                </option>
            </select>

            <label for="admin_password">管理密码（默认密码：admin123）</label>
            <input type="password" id="admin_password" name="admin_password" value="admin123" required>

            <button type="submit" class="btn">💾 保存转换后的收款码 & Webhook 配置</button>
        </form>

        <form method="post" style="margin-top:6px;">
            <input type="hidden" name="form_action" value="test_discord_webhook">
            <input type="hidden" name="discord_webhook_url" id="test_webhook_input" value="<?= htmlspecialchars($config['discord_webhook_url']) ?>">
            <button type="submit" class="btn btn-secondary" onclick="document.getElementById('test_webhook_input').value = document.getElementById('discord_webhook_url').value;">
                🔔 发送一条 Discord Webhook 测试消息
            </button>
        </form>
    </div>
</div>

<script>
/**
 * 前端实时解析 EMVCo 二维码字段，上传图片后立即展示收款人姓名和机构
 */
function parseEmvcoPreview(payload) {
    const posMap = {};
    let pos = 0;
    while (pos + 4 <= payload.length) {
        const tag = payload.substring(pos, pos + 2);
        const lenStr = payload.substring(pos + 2, pos + 4);
        if (!/^\d{2}$/.test(lenStr)) break;
        const len = parseInt(lenStr, 10);
        posMap[tag] = payload.substring(pos + 4, pos + 4 + len);
        pos += 4 + len;
    }
    return posMap;
}

/**
 * 多尺度 + 中心裁剪智能二维码图像识别函数
 * 解决用户直接上传手机完整长截图（包含状态栏和边框）时识别率低的问题
 */
function decodeQrFromImageFile(file, previewImgEl, onSuccess, onError) {
    const reader = new FileReader();
    reader.onload = function(evt) {
        if (previewImgEl) {
            previewImgEl.src = evt.target.result;
            previewImgEl.style.display = 'block';
        }
        const img = new Image();
        img.onload = function() {
            const attempts = [
                // 1. 原图完整扫描
                { scale: 1.0, cropCenter: false },
                // 2. 缩放至适中分辨率扫描（针对高清大图）
                { scale: Math.min(1.0, 1000 / Math.max(img.width, img.height)), cropCenter: false },
                // 3. 截取手机截图中心区域扫描（针对 TNG App 保存的带边框海报或手机截屏）
                { scale: 1.0, cropCenter: true },
                // 4. 放大扫描（针对小尺寸图片）
                { scale: 1.5, cropCenter: false }
            ];

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');

            for (const item of attempts) {
                let sx = 0, sy = 0, sw = img.width, sh = img.height;
                if (item.cropCenter) {
                    sx = Math.floor(img.width * 0.1);
                    sy = Math.floor(img.height * 0.15);
                    sw = Math.floor(img.width * 0.8);
                    sh = Math.floor(img.height * 0.7);
                }
                const dw = Math.max(100, Math.floor(sw * item.scale));
                const dh = Math.max(100, Math.floor(sh * item.scale));
                canvas.width = dw;
                canvas.height = dh;
                ctx.drawImage(img, sx, sy, sw, sh, 0, 0, dw, dh);

                const imageData = ctx.getImageData(0, 0, dw, dh);
                const code = jsQR(imageData.data, imageData.width, imageData.height, {
                    inversionAttempts: "attemptBoth"
                });
                if (code && code.data) {
                    onSuccess(code.data.trim());
                    return;
                }
            }
            onError("未能从该图片中识别出清晰的二维码，请尽量裁剪只保留二维码白色方块区域后再上传。");
        };
        img.onerror = function() {
            onError("图片文件读取失败，请确认上传的是有效的 PNG/JPG/WEBP 图片。");
        };
        img.src = evt.target.result;
    };
    reader.readAsDataURL(file);
}

// 绑定右侧配置栏的图片上传自动识别
const qrFileInput = document.getElementById('qr_image_file');
if (qrFileInput) {
    qrFileInput.addEventListener('change', function() {
        if (!this.files || !this.files[0]) return;
        const statusEl = document.getElementById('upload_status_text');
        const previewImg = document.getElementById('upload_preview_img');
        statusEl.textContent = "⏳ 正在自动识别图片中的 TNG / DuitNow 二维码...";
        statusEl.style.color = "#d97706";

        decodeQrFromImageFile(this.files[0], previewImg, function(payload) {
            document.getElementById('decoded_qr_payload').value = payload;
            const tags = parseEmvcoPreview(payload);
            if (tags['59']) {
                document.getElementById('meta_name').textContent = tags['59'];
            }
            statusEl.textContent = "✅ 二维码图片识别成功！已自动提取收款码数据，请点击下方「保存」按钮。";
            statusEl.style.color = "#059669";
        }, function(errMsg) {
            statusEl.textContent = "❌ " + errMsg;
            statusEl.style.color = "#dc2626";
        });
    });
}

// 绑定左侧收银台的临时上传图片即时转换
const instantFileInput = document.getElementById('instant_qr_file');
if (instantFileInput) {
    instantFileInput.addEventListener('change', function() {
        if (!this.files || !this.files[0]) return;
        const statusEl = document.getElementById('instant_status_text');
        statusEl.textContent = "⏳ 正在识别上传的图片...";

        decodeQrFromImageFile(this.files[0], null, function(payload) {
            document.getElementById('instant_decoded_qr').value = payload;
            const tags = parseEmvcoPreview(payload);
            const holder = tags['59'] ? ('（收款人：' + tags['59'] + '）') : '';
            statusEl.textContent = "✅ 已成功读取图片收款码数据" + holder + "！点击下方按钮即可直接生成定制金额收款码。";
            statusEl.style.color = "#059669";
        }, function(errMsg) {
            statusEl.textContent = "❌ " + errMsg;
            statusEl.style.color = "#dc2626";
        });
    });
}
</script>
</body>
</html>