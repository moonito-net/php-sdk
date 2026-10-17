<?php
// Local-only API fixture. All credentials and decisions are test values.
$body = json_decode(file_get_contents('php://input'), true);
$valid = is_array($body) && filter_var($body['ip'] ?? '', FILTER_VALIDATE_IP);
foreach (['ua'=>2048,'events'=>4096,'path'=>512,'method'=>16,'protocol'=>16,'client_token'=>96,'challenge_pass'=>1024] as $field=>$limit) {
    $value = $body[$field] ?? '';
    preg_match_all('/./us', is_string($value) ? $value : '', $characters);
    $valid = $valid && is_string($value) && count($characters[0]) <= $limit;
}
$headers = $body['headers'] ?? [];
$valid = $valid && is_array($headers) && count($headers) <= 64;
foreach ($headers as $name=>$value) {
    preg_match_all('/./us', $value, $characters);
    $valid = $valid && count($characters[0]) <= 2048
        && !in_array(strtolower($name), ['cookie','authorization','proxy-authorization']);
}
header('Content-Type: application/json');
if (!$valid) {
    http_response_code(400);
    echo '{"error":{"message":"invalid test payload"}}';
    return;
}
$mode = explode('/', trim($_SERVER['REQUEST_URI'], '/'))[0];
if ($mode === 'refused') {
    http_response_code(401);
    echo '{"error":{"message":"dummy credential refused"}}';
    return;
}
$data = ['status'=>['need_to_block'=>$mode==='block','risk'=>['decision'=>$mode]],
    'decision_id'=>'test-decision','nonce'=>'test-nonce','set_client_token'=>['name'=>'__mo_ct','value'=>'test-token','max_age'=>7776000],
    'test_received'=>$body];
if ($mode === 'challenge') $data['challenge_url']='https://challenge.example/check';
echo json_encode(['data'=>$data]);
