#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
pass=0
fail=0

while IFS= read -r file; do
    name="${file#"$root"/}"
    result="$(php -r '
        $file = $argv[1];
        $source = file_get_contents($file);
        if (!preg_match("/--FILE--\n(.*)\n\\?>\\n--EXPECTF--\\n(.*)$/s", $source, $matches)) {
            fwrite(STDERR, "invalid phpt format\n");
            exit(2);
        }
        chdir(dirname($file));
        ob_start();
        eval("?>" . $matches[1]);
        $output = ob_get_clean();
        if ($output === $matches[2]) {
            echo "PASS";
            exit(0);
        }
        echo "FAIL\nexpected:\n" . $matches[2] . "got:\n" . $output;
        exit(1);
    ' "$file" 2>&1)" || true

    if [ "$result" = "PASS" ]; then
        echo "PASS  $name"
        pass=$((pass + 1))
    else
        echo "FAIL  $name"
        echo "$result"
        fail=$((fail + 1))
    fi
done < <(find "$root/tests" -name '*.phpt' | sort)

echo
echo "$pass passed, $fail failed, $((pass + fail)) total"
exit "$fail"
