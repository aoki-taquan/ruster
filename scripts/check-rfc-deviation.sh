#!/bin/bash
# RFC-DEVIATION コメントの構造を検証
# 必須フィールド: reason, impact, issue, plan
# 戻り値: 0 (OK) or 1 (不備あり)

set -euo pipefail

REQUIRED_FIELDS=("reason:" "impact:" "issue:" "plan:")
EXIT_CODE=0

# 全 .rs ファイルから RFC-DEVIATION ブロックを検出
while IFS= read -r file; do
    # RFC-DEVIATION の行番号を取得
    line_nums=$(grep -n "RFC-DEVIATION:" "$file" 2>/dev/null | cut -d: -f1 || true)

    for line_num in $line_nums; do
        # RFC-DEVIATION の後続 10 行を取得してフィールドチェック
        block=$(sed -n "${line_num},$((line_num + 10))p" "$file")

        for field in "${REQUIRED_FIELDS[@]}"; do
            if ! echo "$block" | grep -q "$field"; then
                echo "ERROR: ${file}:${line_num} — RFC-DEVIATION missing '${field}'"
                EXIT_CODE=1
            fi
        done
    done
done < <(find . -name "*.rs" -not -path "./target/*")

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "OK: All RFC-DEVIATION comments have required fields."
fi

exit "$EXIT_CODE"
