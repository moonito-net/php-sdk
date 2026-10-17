<?php
require dirname(__DIR__) . '/vendor-less-autoload.php';

function verify(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}
$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
verify($listener !== false, 'Could not reserve localhost port');
$address = stream_socket_get_name($listener, false);
fclose($listener);
$root = sys_get_temp_dir() . '/moonito-transport-test-' . bin2hex(random_bytes(8));
mkdir($root, 0700);
$pipes = [];
$process = proc_open([PHP_BINARY, '-S', $address, __DIR__.'/fixtures/decision-api.php'],
    [0=>['pipe','r'],1=>['file',$root.'/server.log','a'],2=>['file',$root.'/server.log','a']],$pipes);
verify(is_resource($process), 'Could not start localhost API');
fclose($pipes[0]);
$count = 0;
try {
    $ready = false;
    for ($i=0; $i<100; $i++) {
        $socket = @stream_socket_client('tcp://'.$address, $errno, $error, 0.05);
        if ($socket !== false) { fclose($socket); $ready=true; break; }
        usleep(20000);
    }
    verify($ready, 'Localhost API did not start');
    $transports = [new Moonito\Transport\StreamTransport()];
    if (Moonito\Transport\CurlTransport::available()) $transports[] = new Moonito\Transport\CurlTransport();
    foreach ($transports as $transport) {
        foreach (['block','allow','challenge','refused'] as $mode) {
            foreach ([false,true] as $malformed) {
                $client = new Moonito\Client(Moonito\Config::fromArray([
                    'public_key'=>'dummy','secret_key'=>'dummy','cache_ttl'=>0,
                    'cache_dir'=>$root.'/cache-'.$count,'endpoint'=>'http://'.$address.'/'.$mode,'challenge_action'=>'challenge',
                ]),$transport);
                $server=['HTTP_HOST'=>'example.com','REMOTE_ADDR'=>'127.0.0.1','HTTP_X_FORWARDED_FOR'=>'185.137.164.30',
                    'HTTP_CF_CONNECTING_IP'=>'108.44.42.117','HTTP_USER_AGENT'=>str_repeat('😀',3000),
                    'REQUEST_URI'=>'/'.str_repeat('😀',5000),'REQUEST_METHOD'=>'GET','SERVER_PROTOCOL'=>'HTTP/1.1',
                    'HTTP_AUTHORIZATION'=>'secret','HTTP_PROXY_AUTHORIZATION'=>'secret','HTTP_COOKIE'=>'secret'];
                for ($i=0; $i<100; $i++) $server['HTTP_X_TEST_'.$i]=str_repeat('😀',3000);
                $decision=$client->evaluate($server,['__mo_ct'=>$malformed ? "\xff" : 'test-token','__mo_pass'=>"\xff"]);
                if ($mode==='refused') verify($decision->isDegraded() && $decision->isAllow(),'Refusal changed fail-open behavior');
                else {
                    verify(!$decision->isDegraded() && $decision->action()===$mode,'Transport returned wrong decision: '.get_class($transport).' '.$mode);
                    $received=$decision->raw()['data']['test_received'];
                    verify($received['ip']==='185.137.164.30','Spoofed CF header selected');
                    verify(($received['client_token']??null)===($malformed?null:'test-token'),'Malformed identity was not ignored');
                    verify(!isset($received['challenge_pass']),'Invalid pass forwarded');
                    verify($decision->decisionId()==='test-decision' && $decision->nonce()==='test-nonce','Context missing');
                }
                $count++;
            }
        }
    }
    echo 'PASS: '.$count." real HTTP transport scenarios (curl/streams, decisions, malformed input)\n";
} finally {
    proc_terminate($process);
    proc_close($process);
    if (is_dir($root)) {
        $files=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $file) $file->isDir()?rmdir($file->getPathname()):unlink($file->getPathname());
        rmdir($root);
    }
}
