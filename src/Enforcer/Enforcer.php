<?php

namespace Moonito\Enforcer;

use Moonito\Config;
use Moonito\Decision;

/**
 * Turns a block into whatever the site configured.
 *
 * Behaviour is unchanged from 2.0.1, including the three unwanted-visitor
 * actions, because customers have those settings in production and expect
 * them to keep meaning what they meant.
 */
final class Enforcer
{
    private $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /** Does not return when it acts. */
    public function enforce(Decision $decision): void
    {
        if (!$decision->isBlock()) {
            return;
        }

        if (headers_sent()) {
            // Output has started, so neither a status nor a redirect can be
            // sent. Emitting a PHP warning into the customer's page would
            // break the thing this library was installed to protect.
            return;
        }

        $to = $this->config->unwantedVisitorTo;
        $action = (int) $this->config->unwantedVisitorAction;

        if (!empty($to)) {
            if (is_numeric($to)) {
                http_response_code((int) $to);
                exit;
            }

            if ($action === 2) {
                echo $this->iframe($to);
                exit;
            }

            if ($action === 3) {
                $this->loadContent($to);
                exit;
            }

            $this->noCache();
            header('Location: ' . $to, true, 302);
            exit;
        }

        header('HTTP/1.0 403 Forbidden');
        $this->noCache();
        echo $this->blockedPage();
        exit;
    }

    private function iframe(string $to): string
    {
        return '<iframe src="' . htmlspecialchars($to, ENT_QUOTES) . '" width="100%" height="100%" align="left"></iframe>'
            . ' <style> body { padding: 0; margin: 0; } iframe { margin: 0; padding: 0; border: 0; } </style>';
    }

    private function loadContent(string $to): void
    {
        $options = [
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
            'http' => ['header' => 'User-Agent: ' . (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '')],
        ];

        if (filter_var($to, FILTER_VALIDATE_URL)) {
            $content = @file_get_contents($to, false, stream_context_create($options));

            if ($content !== false) {
                echo str_replace('<head>', '<head><base href="' . htmlspecialchars($to, ENT_QUOTES) . '" />', $content);

                return;
            }

            http_response_code(403);

            return;
        }

        if (file_exists($to)) {
            if (pathinfo($to, PATHINFO_EXTENSION) === 'php') {
                require_once $to;
            } else {
                echo @file_get_contents($to);
            }

            return;
        }

        http_response_code(403);
    }

    private function noCache(): void
    {
        header('Expires: Mon, 23 Jul 1993 05:00:00 GMT');
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Cache-Control: post-check=0, pre-check=0', false);
        header('Pragma: no-cache');
    }

    private function blockedPage(): string
    {
        return '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">'
            . '<html><head><meta name="robots" content="noindex,follow,noarchive"></head>'
            . '<body bgcolor="#EEEEEE" text="#000000">'
            . '<table border="0" cellspacing="0" cellpadding="0" width="70%" align="center"><tr><td valign="top">'
            . '<table border="0" cellspacing="1" cellpadding="1" width="100%" bgcolor="#FF0000"><tr>'
            . '<td bgcolor="#FFFFFF" style="padding:2px 2px 10px 10px;"><br><b>Access Denied!</b><br><br>'
            . 'Oops! It seems like you\'ve encountered our website security measures. '
            . 'Your access has been blocked for security reasons.<br>'
            . 'If you believe this is an error or have any concerns, please contact our support team for assistance.'
            . '<br><br>Thank you for your understanding.<br><br></td></tr></table>'
            . '</td></tr></table></body></html>';
    }
}
