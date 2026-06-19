FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:f9c1da511e00d7072cb2ca41ca02af9090f39581d2efb45a62da7b9fb9dac850

COPY . $SRC/recon
WORKDIR $SRC/recon
COPY .clusterfuzzlite/build.sh $SRC/
