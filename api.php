<?php
declare(strict_types=1);

// 在服务器环境中设置 ACCESS_PASSWORD；未设置时拒绝登录。
const DATA_DIR = __DIR__ . '/private_data';
const DB_FILE = DATA_DIR . '/records.sqlite';
const UPLOAD_DIR = __DIR__ . '/uploads';
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;

ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_name('personal_records_session');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Strict']);
session_start();

function respond(int $status, array $data): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

function body(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > 8 * 1024 * 1024) respond(413, ['error' => '请求过大']);
    try { $value = json_decode($raw, true, 32, JSON_THROW_ON_ERROR); }
    catch (JsonException $e) { respond(400, ['error' => 'JSON 格式错误']); }
    if (!is_array($value) || array_is_list($value)) respond(400, ['error' => '请求必须是 JSON 对象']);
    return $value;
}

function csrf(): void {
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($sent) || !hash_equals($_SESSION['csrf'] ?? '', $sent)) respond(403, ['error' => 'CSRF 验证失败']);
}

function authorized(): void {
    if (empty($_SESSION['authorized'])) respond(401, ['error' => '请先登录']);
}

function database(): PDO {
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0700, true) && !is_dir(DATA_DIR)) throw new RuntimeException('无法创建数据目录');
    file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\nDeny from all\n", LOCK_EX);
    $db = new PDO('sqlite:' . DB_FILE, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $db->exec('PRAGMA busy_timeout = 5000');
    $db->exec('CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT, module TEXT NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)');
    $db->exec('CREATE INDEX IF NOT EXISTS records_module ON records(module)');
    return $db;
}

function schema(string $module): array {
    $schemas = [
        'purchases' => ['name'=>'text','price'=>'number','category'=>'text','purchase_date'=>'date','platform'=>'text','status'=>'text','notes'=>'text'],
        'investments' => ['name'=>'text','type'=>'text','principal'=>'number','current_value'=>'number','purchase_date'=>'date','notes'=>'text'],
        'short_investments' => ['name'=>'text','amount'=>'number','start_date'=>'date','expected_end_date'=>'date','status'=>'text','profit_loss'=>'number','notes'=>'text'],
        'subscriptions' => ['name'=>'text','amount'=>'number','cycle'=>'text','next_renewal_date'=>'date','payment_method'=>'text','status'=>'text'],
        'savings' => ['name'=>'text','target_amount'=>'number','saved_amount'=>'number','deposit_date'=>'date','notes'=>'text'],
        'password_hints' => ['name'=>'text','url'=>'url','image'=>'image','username'=>'text','password_hint'=>'text','notes'=>'text'],
    ];
    if (!isset($schemas[$module])) respond(400, ['error' => '无效模块']);
    return $schemas[$module];
}

function cleanData(string $module, array $input): array {
    $result = [];
    foreach (schema($module) as $key => $type) {
        $v = $input[$key] ?? null;
        if ($v === null || $v === '') { $result[$key] = null; continue; }
        if ($type === 'number') {
            if (!is_numeric($v) || !is_finite((float)$v)) respond(422, ['error' => "$key 必须是数字"]);
            $result[$key] = (float)$v;
        } else {
            if (!is_string($v) || mb_strlen($v, 'UTF-8') > 2000) respond(422, ['error' => "$key 内容无效或过长"]);
            $v = trim($v);
            if ($type === 'date' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $v)) respond(422, ['error' => "$key 日期格式应为 YYYY-MM-DD"]);
            if ($type === 'url' && $v !== '' && (!filter_var($v, FILTER_VALIDATE_URL) || !in_array(strtolower(parse_url($v, PHP_URL_SCHEME) ?: ''), ['http','https'], true))) respond(422, ['error' => 'URL 必须使用 HTTP 或 HTTPS']);
            if ($type === 'image' && $v !== '' && !preg_match('~^uploads/[a-f0-9]{32}\.(png|jpg|webp|gif)$~', $v)) respond(422, ['error' => '图片路径无效']);
            $result[$key] = $v === '' ? null : $v;
        }
    }
    if (!$result['name']) respond(422, ['error' => '名称不能为空']);
    return $result;
}

function recordRow(array $row): array {
    $data = json_decode($row['data'], true, 32, JSON_THROW_ON_ERROR);
    return ['id'=>(int)$row['id'], 'module'=>$row['module'], 'data'=>$data, 'created_at'=>$row['created_at'], 'updated_at'=>$row['updated_at']];
}

function uploadImage(): never {
    if (!is_dir(UPLOAD_DIR) && !mkdir(UPLOAD_DIR, 0755, true) && !is_dir(UPLOAD_DIR)) throw new RuntimeException('无法创建图片目录');
    $bytes = null;
    if (isset($_FILES['image'])) {
        $file = $_FILES['image'];
        if ($file['error'] !== UPLOAD_ERR_OK || $file['size'] > MAX_IMAGE_BYTES) respond(422, ['error'=>'图片上传失败或超过 5MB']);
        $bytes = file_get_contents($file['tmp_name']);
    } else {
        $input = body();
        $encoded = $input['image'] ?? '';
        if (!is_string($encoded) || !preg_match('~^data:image/(?:png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$~', $encoded, $m) || strlen($m[1]) > MAX_IMAGE_BYTES * 2) respond(422, ['error'=>'图片数据无效']);
        $bytes = base64_decode($m[1], true);
    }
    if ($bytes === false || $bytes === null || strlen($bytes) > MAX_IMAGE_BYTES) respond(422, ['error'=>'图片无效或超过 5MB']);
    $info = @getimagesizefromstring($bytes);
    $types = [IMAGETYPE_JPEG=>'jpg', IMAGETYPE_PNG=>'png', IMAGETYPE_WEBP=>'webp', IMAGETYPE_GIF=>'gif'];
    if (!$info || !isset($types[$info[2]]) || $info[0] > 5000 || $info[1] > 5000) respond(422, ['error'=>'仅支持 5000 像素以内的 JPG、PNG、WebP、GIF']);
    $image = @imagecreatefromstring($bytes);
    if (!$image) respond(422, ['error'=>'无法解码图片']);
    $max = 1200;
    $scale = min(1, $max / max(imagesx($image), imagesy($image)));
    $w = max(1, (int)round(imagesx($image) * $scale)); $h = max(1, (int)round(imagesy($image) * $scale));
    $small = imagecreatetruecolor($w, $h);
    imagealphablending($small, false); imagesavealpha($small, true);
    imagecopyresampled($small, $image, 0, 0, 0, 0, $w, $h, imagesx($image), imagesy($image));
    $name = bin2hex(random_bytes(16)) . '.webp';
    $path = UPLOAD_DIR . '/' . $name;
    if (!imagewebp($small, $path, 80)) respond(500, ['error'=>'图片保存失败']);
    imagedestroy($small); imagedestroy($image);
    chmod($path, 0644);
    respond(201, ['path'=>'uploads/' . $name]);
}

try {
    $action = $_GET['action'] ?? '';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($action === 'login' && $method === 'POST') {
        $input = body();
        $accessPassword = getenv('ACCESS_PASSWORD');
        if (!is_string($accessPassword) || strlen($accessPassword) < 16) respond(503, ['error'=>'访问密码尚未配置']);
        if (!is_string($input['password'] ?? null) || !hash_equals($accessPassword, $input['password'])) { usleep(300000); respond(401, ['error'=>'密码错误']); }
        session_regenerate_id(true);
        $_SESSION['authorized'] = true;
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        respond(200, ['ok'=>true, 'csrf_token'=>$_SESSION['csrf']]);
    }
    if ($action === 'session' && $method === 'GET') {
        respond(200, ['authorized'=>!empty($_SESSION['authorized']), 'csrf_token'=>!empty($_SESSION['authorized']) ? ($_SESSION['csrf'] ?? '') : null]);
    }
    authorized();
    if ($action === 'logout' && $method === 'POST') { csrf(); $_SESSION = []; session_destroy(); respond(200, ['ok'=>true]); }
    if ($action === 'upload' && $method === 'POST') { csrf(); uploadImage(); }
    $db = database();
    if ($action === 'export' && $method === 'GET') {
        $rows = $db->query('SELECT * FROM records ORDER BY module, id')->fetchAll();
        header('Content-Disposition: attachment; filename="records-backup-' . date('Y-m-d') . '.json"');
        respond(200, ['exported_at'=>gmdate('c'), 'records'=>array_map('recordRow', $rows)]);
    }
    if ($action !== 'records') respond(404, ['error'=>'接口不存在']);
    $module = $_GET['module'] ?? '';
    if (!is_string($module)) respond(400, ['error'=>'模块无效']);
    schema($module);
    $id = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
    if ($method === 'GET') {
        if (isset($_GET['id'])) {
            if (!$id) respond(400, ['error'=>'ID 无效']);
            $stmt = $db->prepare('SELECT * FROM records WHERE module = ? AND id = ?'); $stmt->execute([$module, $id]);
            $row = $stmt->fetch(); if (!$row) respond(404, ['error'=>'记录不存在']);
            respond(200, ['record'=>recordRow($row)]);
        }
        $stmt = $db->prepare('SELECT * FROM records WHERE module = ? ORDER BY updated_at DESC, id DESC'); $stmt->execute([$module]);
        $rows = array_map('recordRow', $stmt->fetchAll());
        $q = mb_strtolower(trim((string)($_GET['q'] ?? '')), 'UTF-8');
        if ($q !== '') $rows = array_values(array_filter($rows, fn($r) => mb_strpos(mb_strtolower(json_encode($r['data'], JSON_UNESCAPED_UNICODE), 'UTF-8'), $q) !== false));
        respond(200, ['records'=>$rows]);
    }
    csrf();
    if ($method === 'POST') {
        $data = cleanData($module, body()); $now = gmdate('c');
        $stmt = $db->prepare('INSERT INTO records (module,data,created_at,updated_at) VALUES (?,?,?,?)');
        $stmt->execute([$module, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR), $now, $now]);
        respond(201, ['id'=>(int)$db->lastInsertId()]);
    }
    if (!$id) respond(400, ['error'=>'ID 无效']);
    if ($method === 'PUT' || $method === 'PATCH') {
        $stmt = $db->prepare('SELECT data FROM records WHERE module = ? AND id = ?'); $stmt->execute([$module, $id]);
        $old = $stmt->fetchColumn(); if ($old === false) respond(404, ['error'=>'记录不存在']);
        $data = cleanData($module, array_merge(json_decode($old, true, 32, JSON_THROW_ON_ERROR), body()));
        $stmt = $db->prepare('UPDATE records SET data = ?, updated_at = ? WHERE module = ? AND id = ?');
        $stmt->execute([json_encode($data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR), gmdate('c'), $module, $id]);
        respond(200, ['ok'=>true]);
    }
    if ($method === 'DELETE') {
        $stmt = $db->prepare('DELETE FROM records WHERE module = ? AND id = ?'); $stmt->execute([$module, $id]);
        if (!$stmt->rowCount()) respond(404, ['error'=>'记录不存在']);
        respond(200, ['ok'=>true]);
    }
    respond(405, ['error'=>'请求方法不支持']);
} catch (Throwable $e) {
    error_log('api.php: ' . $e->getMessage());
    respond(500, ['error'=>'服务器内部错误']);
}
