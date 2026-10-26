#!/usr/bin/env bash
# 将 inbox-page-app 已分配的邮箱幂等同步到 icloud-api 的「已卖」分组。
#
# 只写 aliases.group_id；label、凭据和启用状态一律不动。
# 分配时间只出现在报告里，不落库。
# 默认 dry-run，加 --apply 才提交事务。
set -euo pipefail

INBOX_HOST="${INBOX_HOST:-35.212.177.44}"
INBOX_SSH_KEY="${INBOX_SSH_KEY:-$HOME/code/my-vps/35.212.177.44/id_ed25519_1panel}"
INBOX_STATE="${INBOX_STATE:-/opt/inbox-page-app/runtime/allocated-addresses.json}"

API_HOST="${API_HOST:-192.168.7.18}"
API_SSH_KEY="${API_SSH_KEY:-$HOME/.ssh/sunxboy_rsa}"
API_PG_CONTAINER="${API_PG_CONTAINER:-postgres}"
API_PG_USER="${API_PG_USER:-postgres}"
API_PG_DB="${API_PG_DB:-icloud_api}"
GROUP_NAME="${GROUP_NAME:-已卖}"

APPLY=0
if [[ $# -eq 1 && "$1" == "--apply" ]]; then
  APPLY=1
elif [[ $# -gt 0 ]]; then
  echo "用法: $0 [--apply]" >&2
  exit 2
fi
if [[ "$GROUP_NAME" == *"'"* ]]; then
  echo "分组名不能包含单引号" >&2
  exit 2
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

ssh_inbox() {
  ssh -o IdentitiesOnly=yes -o ConnectTimeout=10 -i "$INBOX_SSH_KEY" "root@$INBOX_HOST" "$@"
}

ssh_api() {
  ssh -o IdentitiesOnly=yes -o ConnectTimeout=10 -i "$API_SSH_KEY" "sunxianbing@$API_HOST" "$@"
}

# 只取地址与分配日期；取件令牌不离开源服务器。
ssh_inbox "jq -r '.allocations | to_entries[] | [.key, (.value.allocated_at[0:10])] | @tsv' '$INBOX_STATE'" >"$tmp_dir/allocated.tsv"

total=$(wc -l <"$tmp_dir/allocated.tsv" | tr -d ' ')
invalid=0
: >"$tmp_dir/values.sql"
while IFS=$'\t' read -r email allocated_at; do
  if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ || ! "$allocated_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "跳过格式异常的记录: $email" >&2
    invalid=$((invalid + 1))
    continue
  fi
  printf "  ('%s', DATE '%s'),\n" "$email" "$allocated_at" >>"$tmp_dir/values.sql"
done <"$tmp_dir/allocated.tsv"
valid=$(wc -l <"$tmp_dir/values.sql" | tr -d ' ')
if [[ "$valid" -eq 0 ]]; then
  echo "没有可同步的分配记录" >&2
  exit 1
fi

sed '$ s/,$//' "$tmp_dir/values.sql" >"$tmp_dir/values_trimmed.sql"

cat >"$tmp_dir/report.sql" <<'SQL'
DO $check$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM mail_groups WHERE name = '__GROUP_NAME__') THEN
    RAISE EXCEPTION '分组「__GROUP_NAME__」不存在';
  END IF;
END
$check$;

SELECT
  CASE
    WHEN a.id IS NULL THEN '未匹配(icloud-api 中不存在)'
    WHEN a.group_id = (SELECT id FROM mail_groups WHERE name = '__GROUP_NAME__') THEN '已分组(跳过)'
    WHEN a.group_id IS NOT NULL THEN '其他分组(不覆盖)'
    ELSE '待分组'
  END AS status,
  count(*) AS count
FROM sync_allocated s
LEFT JOIN aliases a ON a.address = s.address
GROUP BY 1
ORDER BY 1;

SELECT
  s.address,
  s.allocated_at,
  CASE
    WHEN a.id IS NULL THEN '未匹配(icloud-api 中不存在)'
    WHEN a.group_id = (SELECT id FROM mail_groups WHERE name = '__GROUP_NAME__') THEN '已分组(跳过)'
    WHEN a.group_id IS NOT NULL THEN '其他分组(不覆盖)'
    ELSE '待分组'
  END AS status
FROM sync_allocated s
LEFT JOIN aliases a ON a.address = s.address
ORDER BY status, s.address;
SQL

cat >"$tmp_dir/update.sql" <<'SQL'
UPDATE aliases a
SET group_id = (SELECT id FROM mail_groups WHERE name = '__GROUP_NAME__'),
    updated_at = (extract(epoch FROM now()) * 1000000000)::bigint
FROM sync_allocated s
WHERE a.address = s.address
  AND a.group_id IS NULL;
SQL

# 报告与更新共用同一个临时表；dry-run 用 ROLLBACK 丢弃临时表。
{
  echo "BEGIN;"
  echo "CREATE TEMP TABLE sync_allocated(address citext PRIMARY KEY, allocated_at date) ON COMMIT DROP;"
  echo "INSERT INTO sync_allocated(address, allocated_at) VALUES"
  cat "$tmp_dir/values_trimmed.sql"
  echo ";"
  sed "s/__GROUP_NAME__/$GROUP_NAME/g" "$tmp_dir/report.sql"
  if [[ $APPLY -eq 1 ]]; then
    sed "s/__GROUP_NAME__/$GROUP_NAME/g" "$tmp_dir/update.sql"
    echo "COMMIT;"
  else
    echo "ROLLBACK;"
  fi
} >"$tmp_dir/sync.sql"

echo "数据源: ${total} 条（有效 ${valid}，异常 ${invalid}）；模式: $( [[ $APPLY -eq 1 ]] && echo 'APPLY' || echo 'dry-run' )"
echo "分组: $GROUP_NAME"
echo

ssh_api "docker exec -i '$API_PG_CONTAINER' psql -U '$API_PG_USER' -d '$API_PG_DB' -v ON_ERROR_STOP=1 -A -F '|' -P pager=off" <"$tmp_dir/sync.sql"

if [[ $APPLY -eq 0 ]]; then
  echo
  echo "dry-run 未写入。确认后运行: $0 --apply"
fi
