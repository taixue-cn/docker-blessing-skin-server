<?php

namespace Taixue\Oidc;

class LinkConsistency
{
    public static function assertSubjectOwner(?object $link, int $claimedUid): void
    {
        if ($link && (int) $link->uid !== $claimedUid) {
            throw new OidcFlowException(
                'signed_uid_conflict',
                '太学账号声明的皮肤站账号与既有绑定不一致，请联系管理员处理冲突。'
            );
        }
    }
}
