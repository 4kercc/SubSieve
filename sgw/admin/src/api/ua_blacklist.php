<?php
require_once __DIR__ . '/_auth.php';

$method = $_SERVER['REQUEST_METHOD'];

// GET — 列出封禁UA
if ($method === 'GET') {
    json_out(['ok' => true, 'entries' => read_ua_blacklist()]);
}

// POST — 添加并立即生效
if ($method === 'POST') {
    $body       = json_decode(file_get_contents('php://input'), true) ?? [];
    $ua         = trim($body['ua'] ?? '');
    $comment    = safe_comment($body['comment'] ?? '');
    $redirectUrl = trim($body['redirect_url'] ?? '');

    if (!$ua) json_err('请输入 UA 关键词');
    if (preg_match('/[\r\n]/', $ua)) json_err('UA 关键词不能包含换行');
    // 跳转 URL 合法性校验
    if ($redirectUrl !== '' && !preg_match('#^https?://#i', $redirectUrl)) {
        json_err('跳转 URL 必须以 http:// 或 https:// 开头');
    }
    $redirectUrl = safe_conf_value($redirectUrl);

    $entries = read_ua_blacklist();
    foreach ($entries as $e) {
        if ($e['ua'] === $ua) json_err('该 UA 已在封禁列表中');
    }

    $entries[] = [
        'ua'          => $ua,
        'comment'     => $comment,
        'redirect_url'=> $redirectUrl,
        'added_at'    => date('Y-m-d H:i'),
    ];

    if (!write_ua_blacklist($entries)) json_err('写入UA封禁文件失败，请检查文件权限');
    $reload = nginx_reload();
    json_out(['ok' => true, 'nginx_reloaded' => $reload]);
}

// PATCH — 更新备注或跳转 URL
if ($method === 'PATCH') {
    $body        = json_decode(file_get_contents('php://input'), true) ?? [];
    $ua          = trim($body['ua'] ?? '');
    $comment     = safe_comment($body['comment'] ?? '');
    $redirectUrl = trim($body['redirect_url'] ?? '');

    if (!$ua) json_err('缺少 ua 参数');
    if ($redirectUrl !== '' && !preg_match('#^https?://#i', $redirectUrl)) {
        json_err('跳转 URL 必须以 http:// 或 https:// 开头');
    }
    $redirectUrl = safe_conf_value($redirectUrl);

    $entries = read_ua_blacklist();
    $found   = false;
    foreach ($entries as &$e) {
        if ($e['ua'] === $ua) {
            $e['comment']      = $comment;
            $e['redirect_url'] = $redirectUrl;
            $found = true;
            break;
        }
    }
    unset($e);

    if (!$found) json_err('未找到该UA');
    if (!write_ua_blacklist($entries)) json_err('写入失败，请检查文件权限');
    // 跳转 URL 变更需要 reload nginx
    $reload = isset($body['redirect_url']) ? nginx_reload() : false;
    json_out(['ok' => true, 'nginx_reloaded' => $reload]);
}

// DELETE — 移除并立即生效
if ($method === 'DELETE') {
    $body = json_decode(file_get_contents('php://input'), true) ?? [];
    $ua   = trim($body['ua'] ?? '');

    if (!$ua) json_err('缺少 ua 参数');

    $entries = array_filter(read_ua_blacklist(), fn($e) => $e['ua'] !== $ua);
    if (!write_ua_blacklist(array_values($entries))) json_err('写入UA封禁文件失败，请检查文件权限');
    $reload = nginx_reload();
    json_out(['ok' => true, 'nginx_reloaded' => $reload]);
}

json_err('不支持的请求方式', 405);

// ── 读写 UA 黑名单 ────────────────────────────────────────────

function read_ua_blacklist(): array {
    if (!file_exists(UA_BLACKLIST_JSON)) return [];
    $data = json_decode(file_get_contents(UA_BLACKLIST_JSON), true);
    return is_array($data) ? $data : [];
}

function write_ua_blacklist(array $entries): bool {
    // 写 JSON（含元数据）
    $r1 = file_put_contents(UA_BLACKLIST_JSON, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);

    // 读取UA白名单，生成conf时跳过白名单中的UA
    $whitelist = [];
    if (file_exists(UA_WHITELIST_JSON)) {
        $wl = json_decode(file_get_contents(UA_WHITELIST_JSON), true);
        if (is_array($wl)) {
            $whitelist = array_column($wl, 'ua');
        }
    }

    // 生成 ua_custom.conf（标记封禁，0/1）
    $lines   = ['# 自定义封禁UA - 由 admin 自动生成 | ' . date('Y-m-d H:i:s')];
    $lines[] = 'map $http_user_agent $is_custom_bad_ua {';
    $lines[] = '    default 0;';
    foreach ($entries as $e) {
        if (in_array($e['ua'], $whitelist, true)) continue;
        $ua = str_replace(["\r", "\n"], '', (string)($e['ua'] ?? ''));
        if ($ua === '') continue;
        $pattern = nginx_ua_pattern($ua);
        $cmt     = !empty($e['comment']) ? ' # ' . safe_comment($e['comment']) : '';
        $lines[] = "    \"~*{$pattern}\" 1;{$cmt}";
    }
    $lines[] = '}';
    $r2 = file_put_contents(UA_CUSTOM_CONF, implode("\n", $lines) . "\n", LOCK_EX);

    // 生成 ua_redirect.conf（UA → 301跳转 URL，空字符串=不跳转）
    $rLines   = ['# UA 301跳转配置 - 由 admin 自动生成 | ' . date('Y-m-d H:i:s')];
    $rLines[] = 'map $http_user_agent $ua_custom_redirect {';
    $rLines[] = '    default "";';
    foreach ($entries as $e) {
        if (in_array($e['ua'], $whitelist, true)) continue;
        $ua = str_replace(["\r", "\n"], '', (string)($e['ua'] ?? ''));
        if ($ua === '') continue;
        $redirectUrl = trim($e['redirect_url'] ?? '');
        if ($redirectUrl === '') continue;  // 无跳转 URL 的不写入
        // URL 安全校验（已在写入时校验，此处再兆底）
        if (!preg_match('#^https?://#i', $redirectUrl)) continue;
        $pattern = nginx_ua_pattern($ua);
        // 跳转 URL 加双引号包裹，转义内部双引号
        $safeUrl  = str_replace('"', '\\"', $redirectUrl);
        $cmt      = !empty($e['comment']) ? ' # ' . safe_comment($e['comment']) : '';
        $rLines[] = "    \"~*{$pattern}\" \"{$safeUrl}\";{$cmt}";
    }
    $rLines[] = '}';
    $r3 = file_put_contents(UA_REDIRECT_CONF, implode("\n", $rLines) . "\n", LOCK_EX);

    return $r1 !== false && $r2 !== false && $r3 !== false;
}
