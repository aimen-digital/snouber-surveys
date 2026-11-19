<?php
/**
 * Receives the workshop survey (index.html next to this file): the answers as JSON, voice notes and photos.
 *
 * Everything lands in survey-answers/<survey>/<sid>/ beside public_html on Hostinger (./answers locally), and this script
 * also writes a deny-all .htaccess in that folder on its first run, in case it ever sits under the web root.
 * No database, no third party, nothing in logs. Aimen downloads the folder from Hostinger's file manager,
 * then deletes it once the answers are read (docs/product/workshops.md, section 8).
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

const MAX_JSON = 300 * 1024;               // the answers of one person, with room to spare
const MAX_FILE = 25 * 1024 * 1024;         // a 10-minute voice note is ~2.5 MB; a phone photo up to ~10 MB
const MAX_FILES_PER_SID = 150;
const MAX_BYTES_PER_SID = 400 * 1024 * 1024;
const MAX_REQUESTS_PER_HOUR = 400;         // per address: about 50 questions plus files, several times over

function reply(int $code, string $error = ''): void
{
    http_response_code($code);
    echo json_encode($error === '' ? ['ok' => true] : ['ok' => false, 'error' => $error]);
    exit;
}

/** The file kind from its first bytes ('' when it is none we accept). */
function sniff(string $head): string
{
    if (strncmp($head, "\x1A\x45\xDF\xA3", 4) === 0) return 'webm';              // Chrome, Android
    if (strncmp($head, 'OggS', 4) === 0) return 'ogg';                           // Firefox
    if (strncmp($head, 'ID3', 3) === 0 || strncmp($head, "\xFF\xFB", 2) === 0) return 'mp3';
    if (strncmp($head, "\xFF\xD8\xFF", 3) === 0) return 'jpg';
    if (strncmp($head, "\x89PNG", 4) === 0) return 'png';
    if (strncmp($head, 'RIFF', 4) === 0 && substr($head, 8, 4) === 'WEBP') return 'webp';
    if (substr($head, 4, 4) === 'ftyp') {                                        // ISO files: iPhone audio and photos
        $brand = substr($head, 8, 4);
        return in_array($brand, ['heic', 'heix', 'heim', 'heis', 'hevc', 'hevx', 'mif1', 'msf1'], true) ? 'heic' : 'm4a';
    }
    return '';
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') reply(405, 'method');

// On Hostinger the answers live next to public_html, never inside it: no web request can reach them, and a new
// deploy (which replaces public_html) cannot wipe them. Locally (no public_html above) they stay in ./answers.
$root = __DIR__ . '/answers';
for ($up = __DIR__; dirname($up) !== $up; $up = dirname($up)) {
    if (basename($up) === 'public_html') { $root = dirname($up) . '/survey-answers/' . basename(__DIR__); break; }
}
if (!is_dir($root) && !@mkdir($root, 0700, true)) reply(500, 'storage');
if (!is_file("$root/.htaccess")) {
    file_put_contents("$root/.htaccess",
        "Options -Indexes\n" .
        "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n" .
        "<IfModule !mod_authz_core.c>\n  Order deny,allow\n  Deny from all\n</IfModule>\n");
}
if (!is_file("$root/index.html")) file_put_contents("$root/index.html", '');

// Rate limit per address. The address is only hashed, never written in clear.
$now = time();
$rateFile = "$root/.rate-" . substr(hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '') . __FILE__), 0, 16);
$hits = [];
if (is_file($rateFile)) {
    foreach (explode("\n", (string) file_get_contents($rateFile)) as $t) {
        if ((int) $t > $now - 3600) $hits[] = (int) $t;
    }
}
if (count($hits) >= MAX_REQUESTS_PER_HOUR) reply(429, 'slow down');
$hits[] = $now;
file_put_contents($rateFile, implode("\n", $hits), LOCK_EX);

// One random id per phone (made by the page), one folder per id.
$sid = (string) ($_POST['sid'] ?? '');
if (!preg_match('/^[a-f0-9]{32}$/', $sid)) reply(400, 'sid');
$dir = "$root/$sid";
$kind = (string) ($_POST['kind'] ?? '');

// Forget everything sent from one phone. Only that phone knows its random id (128 bits); the team uses it to
// remove test runs, since Hostinger's tools cannot delete a file outside public_html.
if ($kind === 'forget') {
    foreach (glob("$dir/*") ?: [] as $file) @unlink($file);
    if (is_dir($dir)) @rmdir($dir);
    reply(is_dir($dir) ? 500 : 200, is_dir($dir) ? 'storage' : '');
}

if (!is_dir($dir) && !@mkdir($dir, 0700)) reply(500, 'storage');

if ($kind === 'answers') {
    $json = (string) ($_POST['answers'] ?? '');
    if ($json === '' || strlen($json) > MAX_JSON) reply(413, 'size');
    $data = json_decode($json, true);
    if (!is_array($data)) reply(400, 'json');
    $pretty = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    file_put_contents("$dir/answers.json.tmp", $pretty);
    rename("$dir/answers.json.tmp", "$dir/answers.json");
    $text = is_string($data['readable'] ?? null) ? $data['readable'] : '';
    file_put_contents("$dir/answers.txt.tmp", $text);
    rename("$dir/answers.txt.tmp", "$dir/answers.txt");
    reply(200);
}

if ($kind === 'voice' || $kind === 'photo') {
    $q = (string) ($_POST['q'] ?? '');
    if (!preg_match('/^[a-z_]{1,40}$/', $q)) reply(400, 'q');
    $f = $_FILES['file'] ?? null;
    if (!is_array($f) || ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_uploaded_file($f['tmp_name'])) reply(400, 'file');
    $size = (int) $f['size'];
    if ($size <= 0 || $size > MAX_FILE) reply(413, 'size');

    $stored = glob("$dir/*") ?: [];
    if (count($stored) >= MAX_FILES_PER_SID) reply(413, 'count');
    if (array_sum(array_map('filesize', $stored)) + $size > MAX_BYTES_PER_SID) reply(413, 'total');

    // The type comes from the file's own first bytes, never from what the browser says.
    $ext = sniff((string) file_get_contents($f['tmp_name'], false, null, 0, 16));
    $allowed = $kind === 'voice' ? ['webm', 'ogg', 'm4a', 'mp3'] : ['jpg', 'png', 'webp', 'heic'];
    if (!in_array($ext, $allowed, true)) reply(415, 'type');

    $name = $kind . '-' . $q . '-' . date('Ymd-His') . '-' . bin2hex(random_bytes(3)) . '.' . $ext;
    if (!move_uploaded_file($f['tmp_name'], "$dir/$name")) reply(500, 'storage');
    @chmod("$dir/$name", 0600);
    reply(200);
}

reply(400, 'kind');
