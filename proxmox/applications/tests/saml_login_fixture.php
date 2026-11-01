<?php
// Pure in-memory view tests: no Zabbix database, sessions or filesystem writes.
$login_source = $fixture_source ?? file_get_contents($argv[1]);
class LoginRedirect extends RuntimeException {}
class LoginUrl {
    public function getUrl() { return 'index_sso.php?request=zabbix.php%3Faction%3Dhost.view'; }
}
function getRequest($name) { global $fixture_request; return $fixture_request[$name] ?? null; }
function hasRequest($name) { global $fixture_request; return array_key_exists($name, $fixture_request); }
function redirect($url) { throw new LoginRedirect($url); }
class LoginFixtureStream {
    public $context;
    private $text;
    private $offset = 0;
    public static $files = [];
    public function stream_open($path, $mode, $options, &$opened_path) {
        if ($mode !== 'rb' || !isset(self::$files[$path])) { return false; }
        $this->text = self::$files[$path];
        $opened_path = $path;
        return true;
    }
    public function stream_read($length) {
        $chunk = substr($this->text, $this->offset, $length);
        $this->offset += strlen($chunk);
        return $chunk;
    }
    public function stream_eof() { return $this->offset >= strlen($this->text); }
    public function stream_stat() { return []; }
    public function stream_set_option($option, $arg1, $arg2) { return false; }
}
stream_wrapper_register('loginfixture', LoginFixtureStream::class);
LoginFixtureStream::$files = [
    'loginfixture://web/local/app/views/general.login.php' => $login_source,
    'loginfixture://web/include/views/general.login.php' => '<?php echo "vendor-recovery-form";'
];
$cases = [
    ['normal_entry', [], true, true],
    ['explicit_recovery', ['form' => 'default'], true, false],
    ['local_submission_error', ['enter' => 'Sign in'], true, false],
    ['recovery_submission', ['form' => 'default', 'enter' => 'Sign in'], true, false],
    ['SAML_disabled_recovery', [], false, false],
    ['unknown_form_uses_SAML', ['form' => 'unknown'], true, true],
    ['recovery_marker_exact', ['form' => 'default-extra'], true, true],
    ['non_scalar_marker_cannot_select_recovery', ['form' => ['default']], true, true]
];
$passed = [];
foreach ($cases as [$name, $fixture_request, $enabled, $expected_redirect]) {
    $data = ['saml_login_url' => $enabled ? new LoginUrl() : ''];
    $destination = null;
    ob_start();
    try { include 'loginfixture://web/local/app/views/general.login.php'; }
    catch (LoginRedirect $error) { $destination = $error->getMessage(); }
    $output = ob_get_clean();
    if ($expected_redirect
            ? ($destination !== (new LoginUrl())->getUrl() || $output !== '')
            : ($destination !== null || $output !== 'vendor-recovery-form')) {
        throw new RuntimeException('Login view case refused: '.$name);
    }
    $passed[] = $name;
}
echo json_encode(['status' => 'login_view_fixture_passed', 'cases' => $passed,
    'preserves_original_encoded_return_URL' => true, 'configuration_writes' => 0]);
