# Utopia WAF

Lite & fast micro PHP Web Application Firewall (WAF) rules management library that is **easy to use** and fits naturally inside the [Utopia](https://github.com/utopia-php) ecosystem.

The library ships with:

- A `Condition` builder that mirrors the API of [`Utopia\Database\Query`](https://github.com/utopia-php/database/blob/main/src/Database/Query.php), including JSON parsing helpers and logical operators.
- Action specific rule classes (`Allow`, `Deny`, `Challenge`, `RateLimit`, `Redirect`).
- A dependency-free `Firewall` orchestrator that evaluates rules against any set of request attributes.

## Installation

```bash
composer require utopia-php/waf
```

## Usage

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Utopia\WAF\Condition;
use Utopia\WAF\Firewall;
use Utopia\WAF\Rules\Allow;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Rules\Challenge;
use Utopia\WAF\Rules\RateLimit;
use Utopia\WAF\Rules\Redirect;

$firewall = new Firewall();
$firewall->setAttribute('requestIP', '127.0.0.1');
$firewall->setAttribute('requestMethod', 'GET');
$firewall->setAttribute('requestPath', '/index');
$firewall->setAttribute('headers', [
    'X-Country' => 'US',
]);

$firewall->addRule(new Deny([
    Condition::equal('ip', ['127.0.0.1']),
    Condition::notEqual('path', '/status'),
]));

$firewall->addRule(new Allow([
    Condition::equal('country', ['US']),
    Condition::equal('method', ['GET']),
]));

$firewall->addRule(new Challenge([
    Condition::startsWith('path', '/admin'),
], Challenge::TYPE_CAPTCHA));

$firewall->addRule(new RateLimit([
    Condition::equal('method', ['POST']),
], limit: 100, interval: 3600));

$firewall->addRule(new Redirect([
    Condition::startsWith('path', '/legacy'),
], location: '/new-home', statusCode: 301));

var_dump($firewall->verify()); // bool(true|false)

if ($rule = $firewall->getLastMatchedRule()) {
    echo 'Matched action: ' . $rule->getAction();
}
```

### Building Conditions

Conditions can be created fluently or by parsing JSON definitions:

```php
$condition = Condition::and([
    Condition::equal('ip', ['10.0.0.1']),
    Condition::notEqual('path', '/health'),
]);

$json = $condition->toString();
$parsed = Condition::parse($json);
```

Available operators mirror the database query builder: `equal`, `notEqual`, `lessThan`, `greaterThan`, `contains`, `between`, `startsWith`, `endsWith`, `isNull`, `and`, `or`, and more.

### Rate Limiting

`RateLimit` rules only store the metadata required for external throttling (`limit` + `interval`). Once a rate limit rule matches, the firewall returns `true` and exposes the matched rule via `getLastMatchedRule()` so you can call any third-party rate limiter with the provided metadata.

```php
$firewall->addRule(new RateLimit([
    Condition::equal('ip', ['203.0.113.12']),
], limit: 500, interval: 60));

if ($firewall->verify()) {
    $matched = $firewall->getLastMatchedRule();
    if ($matched instanceof RateLimit) {
        // Invoke your preferred rate limiter here using $matched->getLimit() and $matched->getInterval()
    }
}
```

### Testing Locally

```bash
composer install
composer test
```

## License

MIT
