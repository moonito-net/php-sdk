<?php
require dirname(__DIR__) . '/vendor-less-autoload.php';

function expect(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$resolver = new Moonito\Context\IpResolver(['203.0.113.10'], true);
foreach ([
    ['185.137.164.30','108.44.42.117','108.44.42.117','185.137.164.30'],
    ['127.0.0.1','108.44.42.117','185.137.164.30','185.137.164.30'],
    ['203.0.113.10','108.44.42.117','185.137.164.30','185.137.164.30'],
    ['172.70.1.1','185.137.164.30','','185.137.164.30'],
    ['10.0.0.2','108.44.42.117','185.137.164.30, 172.70.1.1','185.137.164.30'],
] as [$remote,$cf,$xff,$want]) {
    expect($resolver->resolve(['REMOTE_ADDR'=>$remote,'HTTP_CF_CONNECTING_IP'=>$cf,'HTTP_X_FORWARDED_FOR'=>$xff])['ip']===$want,'Incorrect proxy resolution: '.$remote);
}

class InputTransport implements Moonito\Transport\Transport
{
    public $calls=0;
    public function post(string $url,array $body,array $headers,float $connectTimeout,float $timeout): array
    {
        $this->calls++;
        expect(json_encode($body)!==false,'Payload is not valid UTF-8 JSON');
        foreach (['ua'=>2048,'events'=>4096,'path'=>512,'method'=>16,'protocol'=>16] as $field=>$limit) {
            preg_match_all('/./us',$body[$field]??'',$characters);
            expect(count($characters[0])<=$limit,'Payload exceeds limit for '.$field);
        }
        expect(count($body['headers'])<=64,'Too many headers');
        foreach ($body['headers'] as $name=>$value) {
            expect(!in_array(strtolower($name),['cookie','authorization','proxy-authorization']),'Credential forwarded');
            preg_match_all('/./us',$value,$characters);
            expect(count($characters[0])<=2048,'Header exceeds limit');
        }
        return ['ok'=>true,'status'=>200,'error'=>'','body'=>'{"data":{"status":{"need_to_block":true}}}'];
    }
}
$server=['HTTP_HOST'=>'example.com','REMOTE_ADDR'=>'185.137.164.30','HTTP_USER_AGENT'=>str_repeat('😀',3000),
    'REQUEST_URI'=>'/'.str_repeat('😀',5000),'REQUEST_METHOD'=>str_repeat('A',30),'SERVER_PROTOCOL'=>str_repeat('A',30),
    'HTTP_AUTHORIZATION'=>'secret','HTTP_PROXY_AUTHORIZATION'=>'secret','HTTP_COOKIE'=>'session'];
for ($i=0;$i<100;$i++) $server['HTTP_X_TEST_'.$i]=str_repeat('😀',3000);
$directory=sys_get_temp_dir().'/moonito-input-test-'.bin2hex(random_bytes(8));
try {
    $transport=new InputTransport();
    $client=new Moonito\Client(Moonito\Config::fromArray(['public_key'=>'dummy','secret_key'=>'dummy','cache_ttl'=>0,'cache_dir'=>$directory]),$transport);
    expect($client->evaluate($server,['__mo_ct'=>['invalid'],'__mo_pass'=>['invalid']])->isBlock(),'Oversized input bypassed block');
    $server['HTTP_USER_AGENT']="\xff\xfe";
    expect($client->evaluate($server,[])->isBlock(),'Invalid UTF-8 bypassed block');
    expect($client->evaluate($server,['__mo_ct'=>"\xff"])->isBlock(),'Invalid UTF-8 cookie bypassed block');
    expect($transport->calls===3,'API check missing');
    echo "PASS: input limits, UTF-8 safety, and proxy trust\n";
} finally {
    if (is_dir($directory)) {
        $files=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $file) $file->isDir()?rmdir($file->getPathname()):unlink($file->getPathname());
        rmdir($directory);
    }
}
