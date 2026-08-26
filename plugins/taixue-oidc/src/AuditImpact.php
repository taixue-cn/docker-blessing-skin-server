<?php

namespace Taixue\Oidc;

final class AuditImpact
{
    public static function label(?int $uid, ?string $subject): string
    {
        if ($uid !== null) {
            return '已关联账号';
        }
        if (is_string($subject) && trim($subject) !== '') {
            return '已验证太学账号，尚未映射';
        }

        return '未验证账号（端点流量）';
    }
}
