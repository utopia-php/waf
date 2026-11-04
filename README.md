# Utopia WAF

> [!IMPORTANT]
> This repository is a read-only mirror of `packages/waf` in Appwrite's private Cloud repository (appwrite-labs/cloud). Development happens there, so pull requests and issues opened here are closed automatically.

Lite & fast micro PHP Web Application Firewall (WAF) rules management library that is **easy to use** and fits naturally inside the [Utopia](https://github.com/utopia-php) ecosystem.

The library ships with:

- A `Condition` builder that mirrors the API of [`Utopia\Database\Query`](https://github.com/utopia-php/database/blob/main/src/Database/Query.php), including JSON parsing helpers and logical operators.
- Action specific rule classes (`Bypass`, `Deny`, `Challenge`, `RateLimit`, `Redirect`).
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
use Utopia\WAF\Rules\Bypass;
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

$firewall->addRule(new Bypass([
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

Conditions can be created fluently or by encoding/decoding JSON definitions:

```php
$condition = Condition::and([
    Condition::equal('ip', ['10.0.0.1']),
    Condition::notEqual('path', '/health'),
]);

$json = $condition->encode();
$parsed = Condition::decode($json);
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

### Schedules

A rule can be limited to certain days and an optional time window. A rule without a schedule is always active. `verify()` skips rules outside their schedule, so a later rule can still match. Days, dates and times are read on the clock of the schedule's `timezone`, an IANA name such as `Asia/Kolkata`; without one they are UTC.

```php
use Utopia\WAF\Condition;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Schedule;

$deny = new Deny([
    Condition::equal('country', ['US']),
]);

// Weekend nights, 22:00 to 06:00. A window that crosses midnight belongs to the day it starts on.
$deny->setSchedule(Schedule::fromArray([
    'mode' => 'weekly',
    'days' => [5, 6], // ISO weekdays, 1 = Monday to 7 = Sunday
    'startTime' => '22:00',
    'endTime' => '06:00',
    'timezone' => 'America/New_York',
]));
```

| Mode | Needs | Active on |
|------|-------|-----------|
| `daily` | | every day |
| `weekly` | `days` | the listed weekdays |
| `biweekly` | `days`, `anchor` | the listed weekdays in every other week, counting from the week of `anchor` |
| `weekends` | | Saturday and Sunday |
| `everyNDays` | `interval` (2-365), `anchor` | every `interval` days, counting from `anchor` |

`anchor` is a `YYYY-MM-DD` date; a rule is never active before it. `startTime` and `endTime` are `HH:MM` and go together; leave both out for the whole day, and use `endTime: '00:00'` to run until midnight. `Schedule::fromArray()` throws `Utopia\WAF\Exception\Schedule` on anything else, and `Utopia\WAF\Validator\Schedule` wraps the same checks for request input. On a daylight-saving change, a window that starts inside the skipped hour opens when the clock lands past it, and a window inside the repeated hour is active both times that hour occurs. `Firewall::setClock()` replaces `time()` as the source of the current time, for tests.

### Testing Locally

The package is developed in `packages/waf` of appwrite-labs/cloud, which supplies PHPUnit, Pint, PHPStan and Rector. From that repository's root:

```bash
bin/monorepo test waf          # unit tests
bin/monorepo check waf --fix   # Pint, PHPStan, Rector
```

On a standalone checkout of this mirror, the manifest no longer pulls in PHPUnit, so add it first:

```bash
composer install
composer require --dev phpunit/phpunit:^12
composer test
```

## License

MIT
