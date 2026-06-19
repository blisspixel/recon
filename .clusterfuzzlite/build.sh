#!/bin/bash -eu

python3 -m pip install --no-cache-dir --require-hashes -r "$SRC/recon/.clusterfuzzlite/requirements.txt"

export PYTHONPATH="$SRC/recon/src${PYTHONPATH:+:$PYTHONPATH}"

for fuzzer in $(find "$SRC/recon/fuzz" -name '*_fuzzer.py' -print); do
  fuzzer_basename=$(basename -s .py "$fuzzer")
  fuzzer_package=${fuzzer_basename}.pkg

  pyinstaller \
    --distpath "$OUT" \
    --workpath "$WORK/pyinstaller" \
    --specpath "$WORK" \
    --onefile \
    --name "$fuzzer_package" \
    "$fuzzer"

  cat > "$OUT/$fuzzer_basename" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
"\$this_dir/$fuzzer_package" "\$@"
EOF
  chmod +x "$OUT/$fuzzer_basename"
done
