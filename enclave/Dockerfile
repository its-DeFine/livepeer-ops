ARG BASE_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:2

FROM ${BASE_IMAGE}

RUN yum install -y \
    python3 \
    ca-certificates \
  && yum clean all \
  && rm -rf /var/cache/yum

WORKDIR /opt/enclave-signer

COPY requirements.txt ./requirements.txt
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Built on the parent instance via scripts/fetch_kmstool_enclave_cli.sh
COPY kmstool_enclave_cli /kmstool_enclave_cli
COPY libnsm.so /usr/lib64/libnsm.so

COPY signer_server.py ./signer_server.py

ENV PYTHONUNBUFFERED=1
ENV LD_LIBRARY_PATH=/usr/lib64:${LD_LIBRARY_PATH}
ENV KMSTOOL_ENCLAVE_CLI=/kmstool_enclave_cli

CMD ["python3", "/opt/enclave-signer/signer_server.py", "--listen", "vsock://0:5000"]

