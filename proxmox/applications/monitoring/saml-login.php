<?php
// Use Zabbix's local view extension; keep its authentication implementation intact.
// Explicit recovery and local-login submissions retain the unmodified vendor form.
if ($data['saml_login_url'] !== '' && getRequest('form') !== 'default' && !hasRequest('enter')) {
    redirect($data['saml_login_url']->getUrl());
    return;
}

require dirname(__DIR__, 3).'/include/views/general.login.php';
